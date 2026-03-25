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
	"fmt"
	"runtime"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
)

func sliceToRoaring(refs []storage.SeriesRef) *roaring.Bitmap {
	bm := roaring.New()
	vals := make([]uint32, len(refs))
	for i, r := range refs {
		vals[i] = uint32(r)
	}
	bm.AddMany(vals)
	return bm
}

// BenchmarkRoaringVsSlice_Iteration compares sequential Next/At iteration
// between listPostings (sorted slice) and a roaring.Bitmap iterator.
func BenchmarkRoaringVsSlice_Iteration(b *testing.B) {
	for _, count := range []int{1_000, 10_000, 100_000, 1_000_000} {
		refs := make([]storage.SeriesRef, count)
		for i := range refs {
			refs[i] = storage.SeriesRef(i * 4)
		}
		bm := sliceToRoaring(refs)

		b.Run(fmt.Sprintf("count=%d", count), func(b *testing.B) {
			b.Run("slice", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					p := NewListPostings(refs)
					var sum storage.SeriesRef
					for p.Next() {
						sum += p.At()
					}
					require.NotZero(b, sum)
				}
			})
			b.Run("roaring", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					p := newRoaringPostings(bm)
					var sum storage.SeriesRef
					for p.Next() {
						sum += p.At()
					}
					require.NotZero(b, sum)
				}
			})
		})
	}
}

// BenchmarkRoaringVsSlice_Seek compares Seek performance (binary search vs AdvanceIfNeeded).
func BenchmarkRoaringVsSlice_Seek(b *testing.B) {
	for _, count := range []int{10_000, 100_000, 1_000_000} {
		refs := make([]storage.SeriesRef, count)
		for i := range refs {
			refs[i] = storage.SeriesRef(i * 4)
		}
		bm := sliceToRoaring(refs)

		targets := []storage.SeriesRef{
			refs[count/4],
			refs[count/2],
			refs[3*count/4],
			refs[count-1],
		}

		b.Run(fmt.Sprintf("count=%d", count), func(b *testing.B) {
			b.Run("slice", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					for _, target := range targets {
						p := NewListPostings(refs)
						require.True(b, p.Seek(target))
						require.Equal(b, target, p.At())
					}
				}
			})
			b.Run("roaring", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					for _, target := range targets {
						p := newRoaringPostings(bm)
						require.True(b, p.Seek(target))
						require.Equal(b, target, p.At())
					}
				}
			})
		})
	}
}

// BenchmarkRoaringVsSlice_Intersect compares iterator-based Intersect with native Roaring AND.
func BenchmarkRoaringVsSlice_Intersect(b *testing.B) {
	for _, tc := range []struct {
		name    string
		sizes   []int
		stride  int
		offsets []int
	}{
		{
			name:    "two_large_high_overlap",
			sizes:   []int{1_000_000, 800_000},
			stride:  1,
			offsets: []int{0, 100_000},
		},
		{
			name:    "two_large_low_overlap",
			sizes:   []int{1_000_000, 1_000_000},
			stride:  1,
			offsets: []int{0, 900_000},
		},
		{
			name:    "two_medium",
			sizes:   []int{100_000, 50_000},
			stride:  1,
			offsets: []int{0, 50_000},
		},
		{
			name:    "selective_needle",
			sizes:   []int{1_000_000, 100},
			stride:  1,
			offsets: []int{0, 500_000},
		},
		{
			name:    "four_way",
			sizes:   []int{500_000, 400_000, 300_000, 200_000},
			stride:  1,
			offsets: []int{0, 50_000, 100_000, 150_000},
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			slices := make([][]storage.SeriesRef, len(tc.sizes))
			bitmaps := make([]*roaring.Bitmap, len(tc.sizes))
			for i, sz := range tc.sizes {
				s := make([]storage.SeriesRef, sz)
				for j := range s {
					s[j] = storage.SeriesRef(tc.offsets[i] + j*tc.stride)
				}
				slices[i] = s
				bitmaps[i] = sliceToRoaring(s)
			}

			b.Run("iterator", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					its := make([]Postings, len(slices))
					for i, s := range slices {
						its[i] = NewListPostings(s)
					}
					if err := consumePostings(Intersect(its...)); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("roaring_native", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					result := bitmaps[0].Clone()
					for _, bm := range bitmaps[1:] {
						result.And(bm)
					}
					it := result.Iterator()
					var sum uint64
					for it.HasNext() {
						sum += uint64(it.Next())
					}
					runtime.KeepAlive(sum)
				}
			})

			b.Run("roaring_as_postings", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					its := make([]Postings, len(bitmaps))
					for i, bm := range bitmaps {
						its[i] = newRoaringPostings(bm)
					}
					if err := consumePostings(Intersect(its...)); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// BenchmarkRoaringVsSlice_Merge compares loser-tree Merge (union) with native Roaring OR.
func BenchmarkRoaringVsSlice_Merge(b *testing.B) {
	for _, tc := range []struct {
		name    string
		nLists  int
		perList int
	}{
		{"10_lists_x_10k", 10, 10_000},
		{"100_lists_x_1k", 100, 1_000},
		{"1000_lists_x_100", 1000, 100},
		{"10_lists_x_100k", 10, 100_000},
	} {
		b.Run(tc.name, func(b *testing.B) {
			allSlices := make([][]storage.SeriesRef, tc.nLists)
			allBitmaps := make([]*roaring.Bitmap, tc.nLists)
			for i := range tc.nLists {
				s := make([]storage.SeriesRef, tc.perList)
				for j := range s {
					s[j] = storage.SeriesRef(i + j*tc.nLists)
				}
				allSlices[i] = s
				allBitmaps[i] = sliceToRoaring(s)
			}

			b.Run("iterator", func(b *testing.B) {
				b.ReportAllocs()
				ctx := context.Background()
				lps := make([]*listPostings, tc.nLists)
				for b.Loop() {
					for i, s := range allSlices {
						lps[i] = &listPostings{list: s}
					}
					if err := consumePostings(Merge(ctx, lps...)); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("roaring_native", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					result := roaring.New()
					for _, bm := range allBitmaps {
						result.Or(bm)
					}
					it := result.Iterator()
					var sum uint64
					for it.HasNext() {
						sum += uint64(it.Next())
					}
					runtime.KeepAlive(sum)
				}
			})
		})
	}
}

// BenchmarkRoaringVsSlice_Without compares removedPostings with native Roaring ANDNOT.
func BenchmarkRoaringVsSlice_Without(b *testing.B) {
	for _, tc := range []struct {
		name     string
		fullSize int
		dropSize int
	}{
		{"large_full_small_drop", 1_000_000, 1_000},
		{"large_full_medium_drop", 1_000_000, 100_000},
		{"large_full_large_drop", 1_000_000, 900_000},
		{"medium_full_medium_drop", 100_000, 50_000},
	} {
		b.Run(tc.name, func(b *testing.B) {
			full := make([]storage.SeriesRef, tc.fullSize)
			for i := range full {
				full[i] = storage.SeriesRef(i)
			}
			drop := make([]storage.SeriesRef, tc.dropSize)
			for i := range drop {
				drop[i] = storage.SeriesRef(i * (tc.fullSize / tc.dropSize))
			}
			fullBM := sliceToRoaring(full)
			dropBM := sliceToRoaring(drop)

			b.Run("iterator", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					w := Without(NewListPostings(full), NewListPostings(drop))
					if err := consumePostings(w); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("roaring_native", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					result := fullBM.Clone()
					result.AndNot(dropBM)
					it := result.Iterator()
					var sum uint64
					for it.HasNext() {
						sum += uint64(it.Next())
					}
					runtime.KeepAlive(sum)
				}
			})
		})
	}
}

// BenchmarkRoaringVsSlice_Add compares append-to-slice with Roaring.Add for the write path.
func BenchmarkRoaringVsSlice_Add(b *testing.B) {
	for _, count := range []int{10_000, 100_000, 1_000_000} {
		b.Run(fmt.Sprintf("count=%d", count), func(b *testing.B) {
			b.Run("slice", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					s := make([]storage.SeriesRef, 0)
					for i := range count {
						s = appendWithExponentialGrowth(s, storage.SeriesRef(i))
					}
					runtime.KeepAlive(s)
				}
			})

			b.Run("roaring", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					bm := roaring.New()
					for i := range count {
						bm.Add(uint32(i))
					}
					runtime.KeepAlive(bm)
				}
			})
		})
	}
}

// BenchmarkRoaringVsSlice_Delete compares rebuilding slices vs Roaring.Remove.
func BenchmarkRoaringVsSlice_Delete(b *testing.B) {
	for _, tc := range []struct {
		name      string
		totalSize int
		deleteN   int
	}{
		{"100k_delete_100", 100_000, 100},
		{"100k_delete_10k", 100_000, 10_000},
		{"1M_delete_1k", 1_000_000, 1_000},
		{"1M_delete_100k", 1_000_000, 100_000},
	} {
		b.Run(tc.name, func(b *testing.B) {
			original := make([]storage.SeriesRef, tc.totalSize)
			for i := range original {
				original[i] = storage.SeriesRef(i)
			}
			deleteSet := make(map[storage.SeriesRef]struct{}, tc.deleteN)
			stride := tc.totalSize / tc.deleteN
			for i := range tc.deleteN {
				deleteSet[storage.SeriesRef(i*stride)] = struct{}{}
			}

			b.Run("slice_rebuild", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					repl := make([]storage.SeriesRef, 0, len(original))
					for _, id := range original {
						if _, ok := deleteSet[id]; !ok {
							repl = append(repl, id)
						}
					}
					runtime.KeepAlive(repl)
				}
			})

			originalBM := sliceToRoaring(original)
			deleteSlice := make([]uint32, 0, tc.deleteN)
			for ref := range deleteSet {
				deleteSlice = append(deleteSlice, uint32(ref))
			}

			b.Run("roaring_remove", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					bm := originalBM.Clone()
					for _, ref := range deleteSlice {
						bm.Remove(ref)
					}
					runtime.KeepAlive(bm)
				}
			})
		})
	}
}

// BenchmarkRoaringVsSlice_Memory compares heap memory of MemPostings-style storage
// using []SeriesRef slices versus roaring.Bitmap per label pair.
func BenchmarkRoaringVsSlice_Memory(b *testing.B) {
	for _, tc := range []struct {
		name            string
		numSeries       int
		labelsPerSeries int
		uniqueNames     int
		valuesPerName   int
	}{
		{
			name:            "100k_series_typical",
			numSeries:       100_000,
			labelsPerSeries: 10,
			uniqueNames:     20,
			valuesPerName:   5_000,
		},
		{
			name:            "500k_series_typical",
			numSeries:       500_000,
			labelsPerSeries: 10,
			uniqueNames:     20,
			valuesPerName:   25_000,
		},
		{
			name:            "1M_series_typical",
			numSeries:       1_000_000,
			labelsPerSeries: 10,
			uniqueNames:     20,
			valuesPerName:   50_000,
		},
		{
			name:            "1M_series_high_cardinality",
			numSeries:       1_000_000,
			labelsPerSeries: 15,
			uniqueNames:     30,
			valuesPerName:   100_000,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.Run("slice_mempostings", func(b *testing.B) {
				benchmarkMemPostingsMemory(b, tc.numSeries, tc.labelsPerSeries, tc.uniqueNames, tc.valuesPerName)
			})

			b.Run("roaring_mempostings", func(b *testing.B) {
				benchmarkRoaringMemory(b, tc.numSeries, tc.labelsPerSeries, tc.uniqueNames, tc.valuesPerName)
			})
		})
	}
}

func benchmarkRoaringMemory(b *testing.B, numSeries, labelsPerSeries, uniqueNames, valuesPerName int) {
	b.Helper()

	labelNames := make([]string, uniqueNames)
	for i := range labelNames {
		labelNames[i] = fmt.Sprintf("label_name_%04d", i)
	}

	labelValues := make([][]string, uniqueNames)
	for i := range labelValues {
		labelValues[i] = make([]string, valuesPerName)
		for j := range labelValues[i] {
			labelValues[i][j] = fmt.Sprintf("value_%s_%06d", labelNames[i], j)
		}
	}

	type seriesLabels struct {
		lset labels.Labels
	}
	allSeries := make([]seriesLabels, numSeries)
	for i := range allSeries {
		builder := labels.NewBuilder(labels.EmptyLabels())
		for j := 0; j < labelsPerSeries && j < uniqueNames; j++ {
			valIdx := i % len(labelValues[j])
			builder.Set(labelNames[j], labelValues[j][valIdx])
		}
		allSeries[i].lset = builder.Labels()
	}

	runtime.GC()
	runtime.GC()

	b.ResetTimer()
	b.ReportAllocs()

	for n := 0; n < b.N; n++ {
		b.StopTimer()
		m := make(map[string]map[string]*roaring.Bitmap, 512)
		runtime.GC()
		runtime.GC()
		var afterEmpty runtime.MemStats
		runtime.ReadMemStats(&afterEmpty)
		b.StartTimer()

		for i, s := range allSeries {
			ref := uint32(i + 1)
			s.lset.Range(func(l labels.Label) {
				nm, ok := m[l.Name]
				if !ok {
					nm = map[string]*roaring.Bitmap{}
					m[l.Name] = nm
				}
				bm, ok := nm[l.Value]
				if !ok {
					bm = roaring.New()
					nm[l.Value] = bm
				}
				bm.Add(ref)
			})
		}

		b.StopTimer()

		runtime.GC()
		runtime.GC()
		var after runtime.MemStats
		runtime.ReadMemStats(&after)

		memBytes := after.HeapAlloc - afterEmpty.HeapAlloc
		bytesPerSeries := memBytes / uint64(numSeries)

		b.ReportMetric(float64(memBytes), "mempostings_bytes")
		b.ReportMetric(float64(bytesPerSeries), "bytes/series")
		b.ReportMetric(float64(memBytes)/(1024*1024), "mempostings_MiB")

		uniquePairs := 0
		for j := 0; j < labelsPerSeries && j < uniqueNames; j++ {
			seen := map[string]struct{}{}
			for i := range allSeries {
				valIdx := i % len(labelValues[j])
				seen[labelValues[j][valIdx]] = struct{}{}
			}
			uniquePairs += len(seen)
		}
		b.ReportMetric(float64(uniquePairs), "unique_label_pairs")
		b.ReportMetric(float64(memBytes)/float64(uniquePairs), "bytes/label_pair")

		runtime.KeepAlive(m)
		b.StartTimer()
	}
}

// BenchmarkRoaringVsSlice_Memory_Realistic uses a mixed-cardinality label
// distribution that mirrors a real Prometheus setup: a few low-cardinality labels
// (job, env, cluster) where each value matches many series, and several
// high-cardinality labels (pod, instance, container_id) where each value matches
// few series. This exercises the regime where Roaring's compressed containers
// shine on the large posting lists.
func BenchmarkRoaringVsSlice_Memory_Realistic(b *testing.B) {
	for _, tc := range []struct {
		name      string
		numSeries int
		// Each entry: {labelName, numUniqueValues}.
		// refs/value ≈ numSeries/numUniqueValues.
		labels []struct {
			name   string
			values int
		}
	}{
		{
			name:      "1M_mixed_cardinality",
			numSeries: 1_000_000,
			labels: []struct {
				name   string
				values int
			}{
				{"__name__", 500},      // 2000 refs/value
				{"job", 10},            // 100K refs/value
				{"env", 3},             // 333K refs/value
				{"cluster", 5},         // 200K refs/value
				{"namespace", 50},      // 20K refs/value
				{"deployment", 200},    // 5K refs/value
				{"pod", 10_000},        // 100 refs/value
				{"container", 20_000},  // 50 refs/value
				{"instance", 50_000},   // 20 refs/value
				{"node", 1_000},        // 1K refs/value
			},
		},
		{
			name:      "1M_mostly_low_cardinality",
			numSeries: 1_000_000,
			labels: []struct {
				name   string
				values int
			}{
				{"__name__", 200},   // 5K refs/value
				{"job", 5},          // 200K refs/value
				{"env", 2},          // 500K refs/value
				{"region", 4},       // 250K refs/value
				{"cluster", 10},     // 100K refs/value
				{"team", 20},        // 50K refs/value
				{"service", 100},    // 10K refs/value
				{"version", 50},     // 20K refs/value
				{"instance", 1_000}, // 1K refs/value
				{"replica", 3},      // 333K refs/value
			},
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			type seriesLabels struct {
				lset labels.Labels
			}
			allSeries := make([]seriesLabels, tc.numSeries)
			labelNames := make([]string, len(tc.labels))
			labelValues := make([][]string, len(tc.labels))
			for li, ld := range tc.labels {
				labelNames[li] = ld.name
				labelValues[li] = make([]string, ld.values)
				for vi := range labelValues[li] {
					labelValues[li][vi] = fmt.Sprintf("%s_val_%06d", ld.name, vi)
				}
			}
			for i := range allSeries {
				builder := labels.NewBuilder(labels.EmptyLabels())
				for li := range tc.labels {
					valIdx := i % len(labelValues[li])
					builder.Set(labelNames[li], labelValues[li][valIdx])
				}
				allSeries[i].lset = builder.Labels()
			}

			b.Run("slice_mempostings", func(b *testing.B) {
				for n := 0; n < b.N; n++ {
					b.StopTimer()
					mp := NewMemPostings()
					runtime.GC()
					runtime.GC()
					var afterEmpty runtime.MemStats
					runtime.ReadMemStats(&afterEmpty)
					b.StartTimer()

					for i, s := range allSeries {
						mp.Add(storage.SeriesRef(i+1), s.lset)
					}

					b.StopTimer()
					runtime.GC()
					runtime.GC()
					var after runtime.MemStats
					runtime.ReadMemStats(&after)
					memBytes := after.HeapAlloc - afterEmpty.HeapAlloc
					b.ReportMetric(float64(memBytes)/float64(tc.numSeries), "bytes/series")
					b.ReportMetric(float64(memBytes)/(1024*1024), "mempostings_MiB")

					totalPairs := 0
					for _, ld := range tc.labels {
						totalPairs += ld.values
					}
					totalPairs++ // allPostingsKey
					b.ReportMetric(float64(totalPairs), "unique_label_pairs")
					b.ReportMetric(float64(tc.numSeries)/float64(totalPairs), "avg_refs/pair")
					runtime.KeepAlive(mp)
					b.StartTimer()
				}
			})

			b.Run("roaring_mempostings", func(b *testing.B) {
				for n := 0; n < b.N; n++ {
					b.StopTimer()
					mp := NewRoaringMemPostings()
					runtime.GC()
					runtime.GC()
					var afterEmpty runtime.MemStats
					runtime.ReadMemStats(&afterEmpty)
					b.StartTimer()

					for i, s := range allSeries {
						mp.Add(storage.SeriesRef(i+1), s.lset)
					}

					b.StopTimer()
					runtime.GC()
					runtime.GC()
					var after runtime.MemStats
					runtime.ReadMemStats(&after)
					memBytes := after.HeapAlloc - afterEmpty.HeapAlloc
					b.ReportMetric(float64(memBytes)/float64(tc.numSeries), "bytes/series")
					b.ReportMetric(float64(memBytes)/(1024*1024), "mempostings_MiB")

					totalPairs := 0
					for _, ld := range tc.labels {
						totalPairs += ld.values
					}
					totalPairs++ // allPostingsKey
					b.ReportMetric(float64(totalPairs), "unique_label_pairs")
					b.ReportMetric(float64(tc.numSeries)/float64(totalPairs), "avg_refs/pair")
					runtime.KeepAlive(mp)
					b.StartTimer()
				}
			})
		})
	}
}

// BenchmarkRoaringVsSlice_IntersectThenIterate mimics the real query path:
// intersect posting lists then iterate the result to load series.
func BenchmarkRoaringVsSlice_IntersectThenIterate(b *testing.B) {
	const totalSeries = 1_000_000
	allRefs := make([]storage.SeriesRef, totalSeries)
	for i := range allRefs {
		allRefs[i] = storage.SeriesRef(i)
	}

	nameRefs := allRefs[:800_000]
	jobRefs := allRefs[100_000:600_000]
	instanceRefs := allRefs[200_000:300_000]

	nameBM := sliceToRoaring(nameRefs)
	jobBM := sliceToRoaring(jobRefs)
	instanceBM := sliceToRoaring(instanceRefs)

	b.Run("iterator_intersect", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			p := Intersect(
				NewListPostings(nameRefs),
				NewListPostings(jobRefs),
				NewListPostings(instanceRefs),
			)
			var sum storage.SeriesRef
			for p.Next() {
				sum += p.At()
			}
			require.NotZero(b, sum)
		}
	})

	b.Run("roaring_native_then_iterate", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			result := nameBM.Clone()
			result.And(jobBM)
			result.And(instanceBM)
			it := result.Iterator()
			var sum uint64
			for it.HasNext() {
				sum += uint64(it.Next())
			}
			require.NotZero(b, sum)
		}
	})
}

// BenchmarkRoaringVsSlice_Contains tests individual membership checks.
func BenchmarkRoaringVsSlice_Contains(b *testing.B) {
	const count = 1_000_000
	refs := make([]storage.SeriesRef, count)
	for i := range refs {
		refs[i] = storage.SeriesRef(i * 2)
	}
	bm := sliceToRoaring(refs)

	targets := []storage.SeriesRef{0, 100, 10_000, 500_000, 999_998}

	b.Run("slice_binary_search", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, t := range targets {
				p := NewListPostings(refs)
				p.Seek(t)
			}
		}
	})

	b.Run("roaring_contains", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			for _, t := range targets {
				bm.Contains(uint32(t))
			}
		}
	})
}
