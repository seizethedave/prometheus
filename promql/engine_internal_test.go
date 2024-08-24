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

	c := &cseRewriter{
		nodeHash: make(map[parser.Node]uint64),
		cseInfo:  make(map[uint64]*cseInfo),
		bindings: []*parser.LetExpr{},
	}

	c.cseScan(e, nil)

	// There should be 3 distinct hashed values:
	// 1. http_requests_total{}
	// 2. http_requests_total{}+http_requests_total{}
	// 3. (http_requests_total{}+http_requests_total{})

	assert.Len(t, c.cseInfo, 3)
}

// makeLet allows tests to create a LetExpr with a given name and expression,
// plumbing the LetExpr pointer into InExpr.
func makeLet(name string, expr parser.Expr, mkIn func(l *parser.LetExpr) parser.Expr) *parser.LetExpr {
	let := &parser.LetExpr{
		Name: name,
		Expr: expr,
	}
	let.InExpr = mkIn(let)
	return let
}

func TestCseRewrite(t *testing.T) {
	cases := map[string]struct {
		input       string
		expected    parser.Node
		expectedStr string
		expectNoOp  bool
	}{
		"z*z": {
			input: "z{} * z{}",
			expected: makeLet("var0",
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
		"z[w] * z[w]": {
			input: "z{bar='weasel'} * z{bar='weasel'}",
			expected: makeLet("var0",
				&parser.VectorSelector{
					Name: "z",
					LabelMatchers: []*labels.Matcher{
						parser.MustLabelMatcher(labels.MatchEqual, "bar", "weasel"),
						parser.MustLabelMatcher(labels.MatchEqual, model.MetricNameLabel, "z"),
					},
					PosRange: posrange.PositionRange{
						Start: 0,
						End:   15,
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
		"binexpr elimination": {
			input: "64*290 + 64*290",
			// should be rewritten to:
			// let var0 = 64 * 290 in var0 + var0
			expected: makeLet("var0",
				&parser.BinaryExpr{
					Op: parser.MUL,
					LHS: &parser.NumberLiteral{
						Val: 64,
						PosRange: posrange.PositionRange{
							Start: 0,
							End:   2,
						},
					},
					RHS: &parser.NumberLiteral{
						Val: 290,
						PosRange: posrange.PositionRange{
							Start: 3,
							End:   6,
						},
					},
				}, func(let *parser.LetExpr) parser.Expr {
					return &parser.BinaryExpr{
						Op:  parser.ADD,
						LHS: &parser.RefExpr{Ref: let},
						RHS: &parser.RefExpr{Ref: let},
					}
				},
			),
		},
		"different label values": {
			input:      "z{bar='weasel1'} * z{bar='weasel2'}",
			expectNoOp: true,
		},
		"don't eliminate scalars": {
			input:      "123 * 123",
			expectNoOp: true,
		},
		"unary binop": {
			input: "-(1) * -(1)",
			expected: makeLet("var0",
				&parser.UnaryExpr{
					Op: parser.SUB,
					Expr: &parser.ParenExpr{
						Expr: &parser.NumberLiteral{
							Val:      1,
							PosRange: posrange.PositionRange{Start: 2, End: 3},
						},
						PosRange: posrange.PositionRange{Start: 1, End: 4},
					},
				}, func(let *parser.LetExpr) parser.Expr {
					return &parser.BinaryExpr{
						Op:  parser.MUL,
						LHS: &parser.RefExpr{Ref: let},
						RHS: &parser.RefExpr{Ref: let},
					}
				},
			),
		},
		"aggregator": {
			input: "min(a_one) + min(a_one)",
			expected: makeLet("var0",
				&parser.AggregateExpr{
					Op: parser.MIN,
					Expr: &parser.VectorSelector{
						Name: "a_one",
						LabelMatchers: []*labels.Matcher{
							parser.MustLabelMatcher(labels.MatchEqual, model.MetricNameLabel, "a_one"),
						},
						PosRange: posrange.PositionRange{Start: 4, End: 9},
					},
					PosRange: posrange.PositionRange{Start: 0, End: 10},
				},
				func(let *parser.LetExpr) parser.Expr {
					return &parser.BinaryExpr{
						Op:             parser.ADD,
						LHS:            &parser.RefExpr{Ref: let},
						RHS:            &parser.RefExpr{Ref: let},
						VectorMatching: &parser.VectorMatching{},
					}
				},
			),
		},
		"aggregator expr": {
			input: "max by (job) (http_requests{}) + avg by (job) (http_requests{})",
			expected: makeLet("var0",
				&parser.VectorSelector{
					Name: "http_requests",
					LabelMatchers: []*labels.Matcher{
						parser.MustLabelMatcher(labels.MatchEqual, model.MetricNameLabel, "http_requests"),
					},
					PosRange: posrange.PositionRange{Start: 14, End: 29},
				},
				func(let *parser.LetExpr) parser.Expr {
					return &parser.BinaryExpr{
						Op: parser.ADD,
						LHS: &parser.AggregateExpr{
							Op: parser.MAX,
							Expr: &parser.RefExpr{
								Ref: let,
							},
							Param:    nil,
							Grouping: []string{"job"},
							PosRange: posrange.PositionRange{
								Start: 0,
								End:   30,
							},
						},
						RHS: &parser.AggregateExpr{
							Op: parser.AVG,
							Expr: &parser.RefExpr{
								Ref: let,
							},
							Param:    nil,
							Grouping: []string{"job"},
							PosRange: posrange.PositionRange{
								Start: 33,
								End:   63,
							},
						},

						VectorMatching: &parser.VectorMatching{},
					}
				},
			),
		},
	}

	for n, tc := range cases {
		t.Run(n, func(t *testing.T) {
			e, err := parser.ParseExpr(tc.input)
			require.NoError(t, err)

			c := &cseRewriter{
				nodeHash: make(map[parser.Node]uint64),
				cseInfo:  make(map[uint64]*cseInfo),
				bindings: []*parser.LetExpr{},
			}

			c.cseScan(e, nil)
			/*
				fmt.Println(c.cseInfo)
				for _, v := range c.cseInfo {

					for i, n := range v.nodes {
						fmt.Println(i, "parent:", n.parent, "node:", n.node)
					}
				}
			*/

			e2, err := c.rewriteCse(e)
			require.NoError(t, err)

			if tc.expectNoOp {
				tc.expectedStr = tc.input
			}

			if tc.expectedStr != "" {
				// Some expected values are expressible in the grammar, so we
				// parse them to make test cases less laborious.
				tc.expected, err = parser.ParseExpr(tc.expectedStr)
				require.NoError(t, err)
			}

			require.Equal(t, tc.expected, e2, "error on input '%s'", tc.input, "prettified form: "+parser.Prettify(e2))
		})
	}
}
