package audit

import "errors"

type Fanout struct{ sinks []Sink }

func NewFanout(sinks ...Sink) (*Fanout, error) {
	if len(sinks) == 0 {
		return nil, errors.New("at least one required audit sink is required")
	}
	for _, sink := range sinks {
		if sink == nil {
			return nil, errors.New("nil required audit sink")
		}
	}
	return &Fanout{sinks: append([]Sink(nil), sinks...)}, nil
}

func (f *Fanout) Write(event Event) error {
	for _, sink := range f.sinks {
		if err := sink.Write(event); err != nil {
			return errors.New("required audit sink unavailable")
		}
	}
	return nil
}
