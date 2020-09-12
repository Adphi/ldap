package ldap

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type decoder struct {
	useInterface bool
}

func (d *decoder) Decode(e *Entry, v interface{}) error {
	if v == nil {
		return errors.New("cannot decode to nil value")
	}
	if m, ok := v.(Unmarshaler); ok && d.useInterface {
		return m.UnmarshalLDAP(e)
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr {
		return ErrNotPointer
	}
	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return errors.New("cannot decode non struct type")
	}
	if !hasDN(rv) {
		return ErrNoDN
	}
	rt := rv.Type()
	if err := decodeStruct(e, rv, rt); err != nil {
		return err
	}
	return nil
}

func decodeStruct(e *Entry, v reflect.Value, t reflect.Type) error {
	for i := 0; i < v.NumField(); i++ {
		fv := v.Field(i)
		ft := t.Field(i)
		if !unicode.IsUpper(rune(ft.Name[0]))  {
			continue
		}
		info := parseTag(ft)
		if info.ignored {
			continue
		}
		if ft.Anonymous {
			if err := decodeStruct(e, fv, fv.Type()); err != nil {
				return err
			}
			continue
		}
		if strings.ToLower(info.attrName) == "dn" {
			if err := setValue(fv, e.DN); err != nil {
				return err
			}
			continue
		}
		vals, ok := getAttributeValues(e, info.attrName)
		if !ok {
			continue
		}
		if err := decodeStructField(fv, vals); err != nil {
			return err
		}
	}
	return nil
}

func decodeStructField(v reflect.Value, vals []string) error {
	if v.Kind() == reflect.Slice {
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if len(vals) > 0 {
				return setValue(v, vals[0])
			}
			return nil
		}
		for _, va := range vals {
			e := reflect.New(v.Type().Elem()).Elem()
			if err := setValue(e, va); err != nil {
				return err
			}
			v.Set(reflect.Append(v, e))
		}
		return nil
	}
	switch len(vals) {
	case 0:
		return nil
	default:
		return setValue(v, vals[0])
	}
}

func setValue(v reflect.Value, a string) (err error) {
	if v.IsZero() && v.Kind() == reflect.Ptr {
		v.Set(reflect.New(v.Type().Elem()))
	}
	if f, ok := v.Interface().(BinaryDecoder); ok {
		err = f.Decode([]byte(a))
		return
	}
	if f, ok := v.Addr().Interface().(BinaryDecoder); ok {
		err = f.Decode([]byte(a))
		return
	}
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			return err
		}
		v.SetInt(i)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		i, err := strconv.ParseUint(a, 10, 64)
		if err != nil {
			return err
		}
		v.SetUint(i)
		return nil
	case reflect.Float32, reflect.Float64:
		i, err := strconv.ParseFloat(a, 64)
		if err != nil {
			return err
		}
		v.SetFloat(i)
		return nil
	case reflect.String:
		v.SetString(a)
		return nil
	case reflect.Bool:
		v.SetBool(strings.ToUpper(a) == "TRUE")
		return nil
	}
	switch v.Interface().(type) {
	case []byte:
		v.Set(reflect.ValueOf([]byte(a)))
	case time.Time:
		// TODO(adphi): find better time format resolution
		var t time.Time
		if _, err := strconv.Atoi(a); err == nil {
			t = decodeDateTime(a)
		} else {
			// assume DateTime
			t = decodeTime(a)
		}
		v.Set(reflect.ValueOf(t))
	}
	if v.Kind() == reflect.Ptr {
		return setValue(v.Elem(), a)
	}
	return
}

func getAttributeValues(e *Entry, attribute string) ([]string, bool) {
	for _, attr := range e.Attributes {
		if strings.ToLower(attr.Name) == strings.ToLower(attribute) {
			return attr.Values, true
		}
	}
	return nil, false
}

func decodeTime(s string) time.Time {
	layout := "20060102150405.0Z"
	t, err := time.Parse(layout, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func decodeDateTime(t string) time.Time {
	nsec := int64(atoi(t))
	nsec -= 116444736000000000
	nsec *= 100
	return time.Unix(0, nsec).Truncate(time.Second).UTC()
}

func atoi(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}
