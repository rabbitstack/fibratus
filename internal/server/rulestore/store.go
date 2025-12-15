package rulestore

import rulesapi "github.com/rabbitstack/fibratus/api/protobuf/rules/v1"

type Store interface {
	List() (*rulesapi.RuleSet, error)
	Watch() (<-chan *rulesapi.RuleSet, <-chan error)
}
