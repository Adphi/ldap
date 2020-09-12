package ldap

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

type test struct {
	name string
	fn   func(t *testing.T)
}

type TypeNoDN struct {
	String string `ldap:"string"`
}

type TypeEmbed struct {
	DN string
	TypeNoDN
}

type TypeTags struct {
	DN                string `ldap:"dn"`
	DistinguishedName string `ldap:"-"`
	Alpha             string `ldap:"beta"`
}

type binaryEncoder struct {
	wantErr bool
	Value   string
}

func (e *binaryEncoder) Encode() ([]byte, error) {
	if e.wantErr {
		return nil, errors.New("err")
	}
	return []byte(e.Value), nil
}

func (e *binaryEncoder) Decode(v []byte) error {
	if e.wantErr {
		return errors.New("err")
	}
	e.Value = string(v)
	return nil
}

type TypesAll struct {
	DN            string
	Int16         int16 `ldap:"itIsAnInt16"`
	IntZero       int   `ldap:"intZero, omitempty"`
	FloatPtr      *float64
	Uint8         uint8
	StringPtr     *string
	StringSlice   []string
	Raw           []byte   `ldap:"singleRaw"`
	RawSlice      [][]byte `ldap:"multiRaw,omitempty"`
	RawSlice2     [][]byte
	BinaryEncoder binaryEncoder
	Bool          bool
	BoolPtr       *bool  `ldap:"boolPtr"`
	Other         string `ldap:"-"`
	time          time.Time
}

var (
	dn            = "cn=users,dc=example,dc=com"
	encodingTests = []test{
		{
			name: "encode nil",
			fn: func(t *testing.T) {
				e, err := Marshal(nil)
				if err != nil && !strings.Contains(err.Error(), "v is nil") {
					t.Error("expected error when v is nil")
				}
				if e != nil {
					t.Error("expected entry to be nil")
				}
			},
		},
		{
			name: "invalid dn type",
			fn: func(t *testing.T) {
				e, err := Marshal(struct {
					DN int
				}{})
				if err == nil || !errors.Is(err, ErrUnsupportedDNType) {
					t.Errorf("expected ErrUnsupportedDNType, got: %v", err)
				}
				if e != nil {
					t.Error("expected entry to be nil")
				}
			},
		},
		{
			name: "no dn",
			fn: func(t *testing.T) {
				e, err := Marshal(&TypeNoDN{
					String: "test",
				})
				if err == nil || !errors.Is(err, ErrNoDN) {
					t.Errorf("expected ErrUnsupportedDNType, got: %v", err)
				}
				if e != nil {
					t.Error("expected entry to be nil")
				}
			},
		},
		{
			name: "embed struct",
			fn: func(t *testing.T) {
				e, err := Marshal(&TypeEmbed{DN: dn, TypeNoDN: TypeNoDN{
					String: "string",
				}})
				if err != nil {
					t.Errorf("no error expected, got: %v", err)
					t.Fail()
					return
				}
				if e.DN != dn {
					t.Errorf("got dn: %s, expected: %s", e.DN, dn)
				}
				as := e.GetAttributeValues("string")
				if len(as) == 0 {
					t.Error("expected 1 attribute, got 0")
				} else if len(as) > 1 {
					t.Errorf("expected 1 attribute, got %d", len(as))
				} else if as[0] != "string" {
					t.Errorf("expected attribute value 'string' got '%s'", as[0])
				}
			},
		},
		{
			name: "tag override field name",
			fn: func(t *testing.T) {
				e, err := Marshal(&TypeTags{DN: dn, Alpha: "alpha"})
				if err != nil {
					t.Errorf("no error expected, got: %v", err)
					t.Fail()
					return
				}
				if e.DN != dn {
					t.Errorf("got dn: %s, expected: %s", e.DN, dn)
				}
				as := e.GetAttributeValues("beta")
				if len(as) == 0 {
					t.Error("expected 1 attribute, got 0")
				} else if len(as) > 1 {
					t.Errorf("expected 1 attribute, got %d", len(as))
				} else if as[0] != "alpha" {
					t.Errorf("expected attribute value 'alpha' got '%s'", as[0])
				}
				if string(e.GetRawAttributeValue("beta")) != "alpha" {
					t.Error("raw attribute value different from string value")
				}
			},
		},
		{
			name: "all types",
			fn: func(t *testing.T) {
				f := math.MaxFloat64
				s := ""
				e, err := Marshal(&TypesAll{
					DN:            dn,
					Int16:         0,
					IntZero:       0,
					FloatPtr:      &f,
					Uint8:         math.MaxUint8,
					StringPtr:     &s,
					StringSlice:   []string{"one"},
					Raw:           nil,
					RawSlice:      nil,
					BinaryEncoder: binaryEncoder{},
					Other:         "",
				})
				if err != nil {
					t.Errorf("no error expected, got: %v", err)
					t.Fail()
					return
				}
				if e.DN != dn {
					t.Errorf("got dn: %s, expected: %s", e.DN, dn)
				}
				as := e.Attributes
				if len(as) == 0 {
					t.Error("expected 8 attribute, got 0")
					t.Fail()
					return
				}
				if len(as) != 10 {
					t.Errorf("expected 10 attribute, got %d", len(as))
				}
			},
		},
		{
			name: "decode to nil",
			fn: func(t *testing.T) {
				err := Unmarshal(&Entry{}, nil)
				if err == nil {
					t.Error("expected error, go nil")
				}
			},
		},
		{
			name: "decode to non pointer",
			fn: func(t *testing.T) {
				err := Unmarshal(&Entry{}, struct{}{})
				if err == nil || !errors.Is(err, ErrNotPointer) {
					t.Errorf("expected ErrNotPointer, got %v", err)
				}
			},
		},
		{
			name: "decode no dn",
			fn: func(t *testing.T) {
				err := Unmarshal(&Entry{}, &TypeNoDN{})
				if err == nil || !errors.Is(err, ErrNoDN) {
					t.Errorf("expected ErrNoDN, got %v", err)
				}
			},
		},
		{
			name: "decode empty",
			fn: func(t *testing.T) {
				err := Unmarshal(&Entry{}, &TypeEmbed{})
				if err != nil {
					t.Errorf("no error expected, got: %v", err)
					t.Fail()
					return
				}
			},
		},
		{
			name: "decode dn only",
			fn: func(t *testing.T) {
				v := &TypeEmbed{}
				err := Unmarshal(&Entry{DN: dn}, v)
				if err != nil {
					t.Errorf("no error expected, got: %v", err)
					t.Fail()
					return
				}
				if v.DN != dn {
					t.Errorf("expected dn to be '%s', got '%s'", dn, v.DN)
				}
			},
		},
		{
			name: "decode to embed",
			fn: func(t *testing.T) {
				want := &TypeEmbed{DN: dn, TypeNoDN: TypeNoDN{
					String: "one",
				}}
				got := &TypeEmbed{}
				err := Unmarshal(&Entry{
					DN: dn,
					Attributes: []*EntryAttribute{
						NewEntryAttribute("string", []string{"one"}),
						NewEntryAttribute("noop", []string{"noop"}),
					},
				}, got)
				if err != nil {
					t.Errorf("no error expected, got: %v", err)
					t.Fail()
					return
				}
				if !reflect.DeepEqual(want, got) {
					t.Errorf("expected %+v, got %+v", want, got)
				}
			},
		},
		{
			name: "decode to struct with tags",
			fn: func(t *testing.T) {
				want := &TypeTags{DN: dn, Alpha: "4"}
				got := &TypeTags{}
				err := Unmarshal(&Entry{
					DN: dn,
					Attributes: []*EntryAttribute{
						NewEntryAttribute("beta", []string{"4"}),
						NewEntryAttribute("noop", []string{"noop"}),
					},
				}, got)
				if err != nil {
					t.Errorf("no error expected, got: %v", err)
					t.Fail()
					return
				}
				if !reflect.DeepEqual(want, got) {
					t.Errorf("expected %+v, got %+v", want, got)
				}
			},
		},
		{
			name: "decode all types",
			fn: func(t *testing.T) {
				f := math.MaxFloat64
				s := "string pointer"
				b := false
				want := &TypesAll{
					DN:            dn,
					Int16:         4,
					IntZero:       0,
					FloatPtr:      &f,
					Uint8:         math.MaxUint8,
					StringPtr:     &s,
					StringSlice:   []string{"one", "two", "three"},
					Raw:           []byte("one"),
					RawSlice:      [][]byte{[]byte("one"), []byte("two"), []byte("three")},
					BinaryEncoder: binaryEncoder{Value: "whatever"},
					Bool:          true,
					BoolPtr:       &b,
				}
				got := &TypesAll{}
				err := Unmarshal(&Entry{
					DN: dn,
					Attributes: []*EntryAttribute{
						NewEntryAttribute("itIsAnInt16", []string{"4", "22"}),
						NewEntryAttribute("intZero", nil),
						NewEntryAttribute("floatPtr", []string{fmt.Sprintf("%f", f)}),
						NewEntryAttribute("uint8", []string{fmt.Sprintf("%d", want.Uint8)}),
						NewEntryAttribute("stringPtr", []string{s}),
						NewEntryAttribute("stringSlice", []string{"one", "two", "three"}),
						NewEntryAttribute("singleRaw", []string{"one"}),
						NewEntryAttribute("multiRaw", []string{"one", "two", "three"}),
						NewEntryAttribute("binaryEncoder", []string{"whatever"}),
						NewEntryAttribute("bool", []string{"TRUE"}),
						NewEntryAttribute("boolPtr", []string{"FALSE"}),
					},
				}, got)
				if err != nil {
					t.Errorf("no error expected, got: %v", err)
					t.Fail()
					return
				}
				if !reflect.DeepEqual(want, got) {
					t.Errorf("expected %+v, \ngot %+v", want, got)
				}
			},
		},
		{
			name: "decode empty",
			fn: func(t *testing.T) {

			},
		},
		{
			name: "decode empty",
			fn: func(t *testing.T) {

			},
		},
	}
)

func TestEncoding(t *testing.T) {
	for _, v := range encodingTests {
		t.Run(v.name, v.fn)
	}
}
