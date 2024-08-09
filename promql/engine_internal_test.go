// Copyright 2024 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package promql

import (
	"errors"
	"testing"

	"github.com/go-kit/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/prometheus/prometheus/promql/parser/posrange"
	"github.com/prometheus/prometheus/util/annotations"
)

func TestRecoverEvaluatorRuntime(t *testing.T) {
	var output []interface{}
	logger := log.Logger(log.LoggerFunc(func(keyvals ...interface{}) error {
		output = append(output, keyvals...)
		return nil
	}))
	ev := &evaluator{logger: logger}

	expr, _ := parser.ParseExpr("sum(up)")

	var err error

	defer func() {
		require.EqualError(t, err, "unexpected error: runtime error: index out of range [123] with length 0")
		require.Contains(t, output, "sum(up)")
	}()
	defer ev.recover(expr, nil, &err)

	// Cause a runtime panic.
	var a []int
	a[123] = 1
}

func TestRecoverEvaluatorError(t *testing.T) {
	ev := &evaluator{logger: log.NewNopLogger()}
	var err error

	e := errors.New("custom error")

	defer func() {
		require.EqualError(t, err, e.Error())
	}()
	defer ev.recover(nil, nil, &err)

	panic(e)
}

func TestRecoverEvaluatorErrorWithWarnings(t *testing.T) {
	ev := &evaluator{logger: log.NewNopLogger()}
	var err error
	var ws annotations.Annotations

	warnings := annotations.New().Add(errors.New("custom warning"))
	e := errWithWarnings{
		err:      errors.New("custom error"),
		warnings: warnings,
	}

	defer func() {
		require.EqualError(t, err, e.Error())
		require.Equal(t, warnings, ws, "wrong warning message")
	}()
	defer ev.recover(nil, &ws, &err)

	panic(e)
}

func TestCseScan(t *testing.T) {
	e, err := parser.ParseExpr("(http_requests_total{} + http_requests_total{})")
	require.NoError(t, err)

	nodeHash := make(map[parser.Node]uint64)
	cseInfo := make(map[uint64]*cseInfo)
	cseScan(e, nil, cseInfo, nodeHash)

	// There should be 3 distinct hashed values:
	// 1. http_requests_total{}
	// 2. http_requests_total{}+http_requests_total{}
	// 3. (http_requests_total{}+http_requests_total{})

	assert.Len(t, cseInfo, 3)
}

// withLet allows tests to create a LetExpr with a given name and expression,
// and with the let ptr plumbed into the InExpr.
func withLet(name string, expr parser.Expr, mkIn func(l *parser.LetExpr) parser.Expr) *parser.LetExpr {
	let := &parser.LetExpr{
		Name: name,
		Expr: expr,
	}
	let.InExpr = mkIn(let)
	return let
}

func TestCseRewrite(t *testing.T) {
	cases := map[string]struct {
		input    string
		expected parser.Node
	}{
		"z*z": {
			"z{} * z{}",
			withLet("var0",
				&parser.VectorSelector{
					Name: "z",
					LabelMatchers: []*labels.Matcher{
						parser.MustLabelMatcher(labels.MatchEqual, model.MetricNameLabel, "z"),
					},
					PosRange: posrange.PositionRange{
						Start: 0,
						End:   3,
					},
				}, func(let *parser.LetExpr) parser.Expr {
					return &parser.BinaryExpr{
						Op:             parser.MUL,
						LHS:            &parser.RefExpr{Ref: let},
						RHS:            &parser.RefExpr{Ref: let},
						VectorMatching: &parser.VectorMatching{},
					}
				},
			),
		},
		/*
			"z_w*z_w": {
				"z{bar='weasel'} * z{bar='weasel'}",
				withLet("var0",
					&parser.VectorSelector{
						Name: "z",
						LabelMatchers: []*labels.Matcher{
							parser.MustLabelMatcher(labels.MatchEqual, model.MetricNameLabel, "z"),
						},
						PosRange: posrange.PositionRange{
							Start: 0,
							End:   3,
						},
					}, func(let *parser.LetExpr) parser.Expr {
						return &parser.BinaryExpr{
							Op:             parser.MUL,
							LHS:            &parser.RefExpr{Ref: let},
							RHS:            &parser.RefExpr{Ref: let},
							VectorMatching: &parser.VectorMatching{},
						}
					},
				),
			},
		*/
	}

	for n, c := range cases {
		t.Run(n, func(t *testing.T) {
			e, err := parser.ParseExpr(c.input)
			require.NoError(t, err)

			nodeHash := make(map[parser.Node]uint64)
			cseInfo := make(map[uint64]*cseInfo)
			cseScan(e, nil, cseInfo, nodeHash)

			e2, err := rewriteCse(e, nodeHash, cseInfo)
			require.NoError(t, err)
			require.Equal(t, c.expected, e2, "error on input '%s'", c.input)

			//println(parser.Prettify(e2))
		})
	}
}
