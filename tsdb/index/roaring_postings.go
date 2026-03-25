// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package index

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
)

// RoaringMemPostings holds postings list for series ID per label pair,
// backed by 32-bit Roaring bitmaps instead of sorted slices.
// Series refs must fit in uint32.
type RoaringMemPostings struct {
	mtx sync.RWMutex
	m   map[string]map[string]*roaring.Bitmap
	lvs map[string][]string
}

// NewRoaringMemPostings returns a RoaringMemPostings ready for reads and writes.
func NewRoaringMemPostings() *RoaringMemPostings {
	return &RoaringMemPostings{
		m:   make(map[string]map[string]*roaring.Bitmap, defaultLabelNamesMapSize),
		lvs: make(map[string][]string, defaultLabelNamesMapSize),
	}
}

// NewUnorderedRoaringMemPostings returns a RoaringMemPostings. Roaring bitmaps
// are always sorted, so this is identical to NewRoaringMemPostings.
func NewUnorderedRoaringMemPostings() *RoaringMemPostings {
	return NewRoaringMemPostings()
}

// Symbols returns an iterator over all unique name and value strings, in order.
func (p *RoaringMemPostings) Symbols() StringIter {
	p.mtx.RLock()
	lvs := make(map[string][]string, len(p.lvs))
	for k, v := range p.lvs {
		lvs[k] = v
	}
	p.mtx.RUnlock()

	symbols := make(map[string]struct{}, defaultLabelNamesMapSize)
	for n, labelValues := range lvs {
		symbols[n] = struct{}{}
		for _, v := range labelValues {
			symbols[v] = struct{}{}
		}
	}

	res := make([]string, 0, len(symbols))
	for k := range symbols {
		res = append(res, k)
	}

	slices.Sort(res)
	return NewStringListIter(res)
}

// SortedKeys returns a list of sorted label keys of the postings.
func (p *RoaringMemPostings) SortedKeys() []labels.Label {
	p.mtx.RLock()
	keys := make([]labels.Label, 0, len(p.m))
	for n, e := range p.m {
		for v := range e {
			keys = append(keys, labels.Label{Name: n, Value: v})
		}
	}
	p.mtx.RUnlock()

	slices.SortFunc(keys, func(a, b labels.Label) int {
		if cmp := strings.Compare(a.Name, b.Name); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Value, b.Value)
	})
	return keys
}

// LabelNames returns all the unique label names.
func (p *RoaringMemPostings) LabelNames() []string {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	n := len(p.m)
	if n == 0 {
		return nil
	}

	names := make([]string, 0, n-1)
	for name := range p.m {
		if name != allPostingsKey.Name {
			names = append(names, name)
		}
	}
	return names
}

// LabelValues returns label values for the given name.
func (p *RoaringMemPostings) LabelValues(_ context.Context, name string, hints *storage.LabelHints) []string {
	p.mtx.RLock()
	values := p.lvs[name]
	p.mtx.RUnlock()

	if hints != nil && hints.Limit > 0 && len(values) > hints.Limit {
		values = values[:hints.Limit]
	}

	return slices.Clone(values)
}

// Stats calculates the cardinality statistics from postings.
func (p *RoaringMemPostings) Stats(label string, limit int, labelSizeFunc func(string, string, uint64) uint64) *PostingsStats {
	var size uint64
	p.mtx.RLock()

	metrics := &maxHeap{}
	lbls := &maxHeap{}
	labelValueLength := &maxHeap{}
	labelValuePairs := &maxHeap{}
	numLabelPairs := 0

	metrics.init(limit)
	lbls.init(limit)
	labelValueLength.init(limit)
	labelValuePairs.init(limit)

	for n, e := range p.m {
		if n == "" {
			continue
		}
		lbls.push(Stat{Name: n, Count: uint64(len(e))})
		numLabelPairs += len(e)
		size = 0
		for name, bm := range e {
			seriesCnt := bm.GetCardinality()
			if n == label {
				metrics.push(Stat{Name: name, Count: seriesCnt})
			}
			labelValuePairs.push(Stat{Name: n + "=" + name, Count: seriesCnt})
			size += labelSizeFunc(n, name, seriesCnt)
		}
		labelValueLength.push(Stat{Name: n, Count: size})
	}

	p.mtx.RUnlock()

	return &PostingsStats{
		CardinalityMetricsStats: metrics.get(),
		CardinalityLabelStats:   lbls.get(),
		LabelValueStats:         labelValueLength.get(),
		LabelValuePairsStats:    labelValuePairs.get(),
		NumLabelPairs:           numLabelPairs,
	}
}

// All returns a postings list over all documents ever added.
func (p *RoaringMemPostings) All() Postings {
	return p.Postings(context.Background(), allPostingsKey.Name, allPostingsKey.Value)
}

// EnsureOrder is a no-op for Roaring bitmaps since they are always sorted.
func (p *RoaringMemPostings) EnsureOrder(_ int) {}

// Delete removes all ids in the given map from the postings lists.
func (p *RoaringMemPostings) Delete(deleted map[storage.SeriesRef]struct{}, affected map[labels.Label]struct{}) {
	p.mtx.Lock()
	defer p.mtx.Unlock()

	delBM := roaring.New()
	for ref := range deleted {
		delBM.Add(uint32(ref))
	}

	affectedLabelNames := map[string]struct{}{}
	process := func(l labels.Label) {
		bm := p.m[l.Name][l.Value]
		if bm == nil {
			return
		}
		// Clone so readers holding a reference to the old bitmap are not affected.
		newBM := bm.Clone()
		newBM.AndNot(delBM)
		if newBM.GetCardinality() > 0 {
			p.m[l.Name][l.Value] = newBM
		} else {
			delete(p.m[l.Name], l.Value)
			affectedLabelNames[l.Name] = struct{}{}
		}
	}

	i := 0
	for l := range affected {
		i++
		process(l)
		if i%512 == 0 {
			p.unlockWaitAndLockAgain()
		}
	}
	process(allPostingsKey)

	i = 0
	for name := range affectedLabelNames {
		i++
		if i%512 == 0 {
			p.unlockWaitAndLockAgain()
		}

		if len(p.m[name]) == 0 {
			delete(p.m, name)
			delete(p.lvs, name)
			continue
		}

		lvs := make([]string, 0, exponentialSliceGrowthFactor*len(p.m[name]))
		for v := range p.m[name] {
			lvs = append(lvs, v)
		}
		p.lvs[name] = lvs
	}
}

func (p *RoaringMemPostings) unlockWaitAndLockAgain() {
	p.mtx.Unlock()
	p.mtx.RLock()
	p.mtx.RUnlock() //nolint:staticcheck // SA2001: intentionally empty critical section.
	time.Sleep(time.Millisecond)
	p.mtx.Lock()
}

// Iter calls f for each postings list. It aborts if f returns an error and returns it.
func (p *RoaringMemPostings) Iter(f func(labels.Label, Postings) error) error {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	for n, e := range p.m {
		for v, bm := range e {
			if err := f(labels.Label{Name: n, Value: v}, newRoaringPostings(bm)); err != nil {
				return err
			}
		}
	}
	return nil
}

// Add a label set to the postings index.
func (p *RoaringMemPostings) Add(id storage.SeriesRef, lset labels.Labels) {
	p.mtx.Lock()
	lset.Range(func(l labels.Label) {
		p.addFor(id, l)
	})
	p.addFor(id, allPostingsKey)
	p.mtx.Unlock()
}

func (p *RoaringMemPostings) addFor(id storage.SeriesRef, l labels.Label) {
	nm, ok := p.m[l.Name]
	if !ok {
		nm = map[string]*roaring.Bitmap{}
		p.m[l.Name] = nm
	}
	bm, ok := nm[l.Value]
	if !ok {
		bm = roaring.New()
		nm[l.Value] = bm
		p.lvs[l.Name] = appendWithExponentialGrowth(p.lvs[l.Name], l.Value)
	}
	bm.Add(uint32(id))
}

// PostingsForLabelMatching returns a merged postings list for all values
// of the given label name that satisfy match.
func (p *RoaringMemPostings) PostingsForLabelMatching(ctx context.Context, name string, match func(string) bool) Postings {
	p.mtx.RLock()
	readOnlyLabelValues := p.lvs[name]
	p.mtx.RUnlock()

	vals := make([]string, 0, len(readOnlyLabelValues))
	for i, v := range readOnlyLabelValues {
		if i%checkContextEveryNIterations == 0 && ctx.Err() != nil {
			return ErrPostings(ctx.Err())
		}
		if match(v) {
			vals = append(vals, v)
		}
	}

	if len(vals) == 0 {
		return EmptyPostings()
	}

	p.mtx.RLock()
	e := p.m[name]
	bitmaps := make([]*roaring.Bitmap, 0, len(vals))
	for _, v := range vals {
		if bm, ok := e[v]; ok {
			bitmaps = append(bitmaps, bm)
		}
	}
	p.mtx.RUnlock()

	return p.mergedRoaringPostings(bitmaps)
}

// Postings returns a postings iterator for the given label values.
func (p *RoaringMemPostings) Postings(_ context.Context, name string, values ...string) Postings {
	p.mtx.RLock()
	postingsMapForName := p.m[name]
	bitmaps := make([]*roaring.Bitmap, 0, len(values))
	for _, value := range values {
		if bm := postingsMapForName[value]; bm != nil {
			bitmaps = append(bitmaps, bm)
		}
	}
	p.mtx.RUnlock()

	return p.mergedRoaringPostings(bitmaps)
}

// PostingsForAllLabelValues returns a merged postings list for all values of the given label name.
func (p *RoaringMemPostings) PostingsForAllLabelValues(_ context.Context, name string) Postings {
	p.mtx.RLock()
	e := p.m[name]
	bitmaps := make([]*roaring.Bitmap, 0, len(e))
	for _, bm := range e {
		if bm.GetCardinality() > 0 {
			bitmaps = append(bitmaps, bm)
		}
	}
	p.mtx.RUnlock()

	return p.mergedRoaringPostings(bitmaps)
}

func (p *RoaringMemPostings) mergedRoaringPostings(bitmaps []*roaring.Bitmap) Postings {
	if len(bitmaps) == 0 {
		return EmptyPostings()
	}
	if len(bitmaps) == 1 {
		return newRoaringPostings(bitmaps[0])
	}
	return newRoaringPostings(roaring.FastOr(bitmaps...))
}

// roaringPostings adapts a roaring.Bitmap iterator to the Postings interface.
type roaringPostings struct {
	it  roaring.IntPeekable
	cur storage.SeriesRef
}

func newRoaringPostings(bm *roaring.Bitmap) *roaringPostings {
	return &roaringPostings{it: bm.Iterator()}
}

func (rp *roaringPostings) Next() bool {
	if rp.it.HasNext() {
		rp.cur = storage.SeriesRef(rp.it.Next())
		return true
	}
	return false
}

func (rp *roaringPostings) Seek(v storage.SeriesRef) bool {
	if rp.cur >= v {
		return true
	}
	rp.it.AdvanceIfNeeded(uint32(v))
	if rp.it.HasNext() {
		rp.cur = storage.SeriesRef(rp.it.Next())
		return rp.cur >= v
	}
	return false
}

func (rp *roaringPostings) At() storage.SeriesRef {
	return rp.cur
}

func (*roaringPostings) Err() error {
	return nil
}
