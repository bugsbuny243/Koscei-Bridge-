package nodeshield

import (
	"context"
	"errors"
	"io"
	"testing"
)

type sliceEventSource struct { events []RuntimeEvent; index int; err error }
func (s *sliceEventSource) Next(_ context.Context) (RuntimeEvent,error){if s.index<len(s.events){e:=s.events[s.index];s.index++;return e,nil};if s.err!=nil{return RuntimeEvent{},s.err};return RuntimeEvent{},io.EOF}
type capabilityEventSource struct{sliceEventSource;caps RuntimeCapabilities}
func(s *capabilityEventSource)Capabilities()RuntimeCapabilities{return s.caps}

func TestGuardStopsAfterStartupKill(t *testing.T){source:=&capabilityEventSource{caps:RuntimeCapabilities{Mode:EnforcementKillOnly,ArtifactIdentity:true}};enforcer:=&fakeEnforcer{};guard:=Guard{Source:source,Supervisor:Supervisor{WorkloadID:"w1",ObservedArtifactSHA256:"tampered",Policy:RuntimePolicy{ArtifactSHA256:"approved"},Audit:&fakeAudit{},Enforcer:enforcer}};if err:=guard.Run(context.Background());err!=nil{t.Fatalf("expected clean stop after kill, got %v",err)};if enforcer.killed!=1{t.Fatalf("expected one kill, got %d",enforcer.killed)}}
func TestGuardKillOnlyEscalatesDenyToKill(t *testing.T){source:=&capabilityEventSource{sliceEventSource:sliceEventSource{events:[]RuntimeEvent{{Kind:EventNetworkConnect,Destination:"evil.example:443"}}},caps:RuntimeCapabilities{Mode:EnforcementKillOnly,ArtifactIdentity:true}};enforcer:=&fakeEnforcer{};guard:=Guard{Source:source,Supervisor:Supervisor{WorkloadID:"w1",ObservedArtifactSHA256:"abc",Policy:RuntimePolicy{ArtifactSHA256:"abc",AllowedHosts:[]string{"api.example.com:443"}},Audit:&fakeAudit{},Enforcer:enforcer}};if err:=guard.Run(context.Background());err!=nil{t.Fatalf("kill-only guard failed: %v",err)};if enforcer.denied!=0||enforcer.killed!=1{t.Fatalf("kill-only must terminate, got %#v",enforcer)}}
func TestGuardTreatsEOFAsCleanStop(t *testing.T){guard:=Guard{Source:&sliceEventSource{},Supervisor:Supervisor{ObservedArtifactSHA256:"abc",Policy:RuntimePolicy{ArtifactSHA256:"abc"},Audit:&fakeAudit{}}};if err:=guard.Run(context.Background());err!=nil{t.Fatalf("expected EOF clean stop, got %v",err)}}
func TestGuardReturnsSourceFailure(t *testing.T){guard:=Guard{Source:&sliceEventSource{err:errors.New("collector failed")},Supervisor:Supervisor{ObservedArtifactSHA256:"abc",Policy:RuntimePolicy{ArtifactSHA256:"abc"},Audit:&fakeAudit{}}};if err:=guard.Run(context.Background());err==nil{t.Fatal("expected collector failure")}}
func TestGuardRejectsObserveOnlyWithoutAudit(t *testing.T){guard:=Guard{Source:&sliceEventSource{},Supervisor:Supervisor{ObservedArtifactSHA256:"abc",Policy:RuntimePolicy{ArtifactSHA256:"abc"}}};if err:=guard.Run(context.Background());err==nil{t.Fatal("expected observe-only mode without audit to fail")}}
func TestGuardRejectsObserveOnlyCollectorWhenPreActionRequired(t *testing.T){source:=&capabilityEventSource{caps:RuntimeCapabilities{Mode:EnforcementObserveOnly,ArtifactIdentity:true}};guard:=Guard{Source:source,RequirePreAction:true};if err:=guard.Run(context.Background());err==nil{t.Fatal("expected pre-action requirement to reject observe-only collector")}}
func TestGuardAcceptsCapabilityAwarePreActionCollector(t *testing.T){source:=&capabilityEventSource{sliceEventSource:sliceEventSource{err:errors.New("done")},caps:RuntimeCapabilities{Mode:EnforcementPreAction,ArtifactIdentity:true,NetworkConnect:true,FileWrite:true,ProcessExec:true,PrivilegeChange:true}};guard:=Guard{Source:source,RequirePreAction:true,Supervisor:Supervisor{Enforcer:&fakeEnforcer{},Audit:&fakeAudit{},ObservedArtifactSHA256:"abc",Policy:RuntimePolicy{ArtifactSHA256:"abc"}}};if err:=guard.Run(context.Background());err==nil{t.Fatal("expected collector end error after capability validation")}}
