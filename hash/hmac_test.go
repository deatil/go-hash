package hash

import (
    "fmt"
    "testing"
)

var hmacMd5Tests = []struct {
    input  string
    secret string
    output string
}{
    {"sdfgsdgfsdfg123132", "pass123", "bf4ce19abed97f9d852c5055d08fc188"},
    {"dfg.;kp[jewijr0-34lsd", "pass123", "d273f8e00fad1b2bd6b048b2b6aa1cf2"},
    {"123123", "pass123", "12c3626311950ac87858b935e1107269"},
}

func Test_HmacMD5(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range hmacMd5Tests {
        e := FromString(test.input).HmacMd5([]byte(test.secret))

        t.Run(fmt.Sprintf("HmacMD5_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "HmacMD5")
            assert(test.output, e.ToHexString(), "HmacMD5")
        })
    }
}

func Test_NewHmacMD5(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range hmacMd5Tests {
        e := Hashing().NewHmacMd5([]byte(test.secret)).
            Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewHmacMD5_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewHmacMD5")
            assert(test.output, e.ToHexString(), "NewHmacMD5")
        })
    }
}

// ===========

var hmacSHA1Tests = []struct {
    input  string
    secret string
    output string
}{
    {"sdfgsdgfsdfg123132", "pass123", "4ba7dc0364e2c375a0ba1fdacdf0a7a1d24b00d6"},
    {"dfg.;kp[jewijr0-34lsd", "pass123", "11a43b22a8449fc36918873ac32fd5a99e466c3d"},
    {"123123", "pass123", "2bc70da9a375a9d9481935eee5ac4e374b33ed8e"},
}

func Test_HmacSHA1(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range hmacSHA1Tests {
        e := FromString(test.input).HmacSHA1([]byte(test.secret))

        t.Run(fmt.Sprintf("HmacSHA1_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "HmacSHA1")
            assert(test.output, e.ToHexString(), "HmacSHA1")
        })
    }
}

func Test_NewHmacSHA1(t *testing.T) {
    assert := assertT(t)
    assertError := assertErrorT(t)

    for index, test := range hmacSHA1Tests {
        e := Hashing().NewHmacSHA1([]byte(test.secret)).
            Write([]byte(test.input)).Sum(nil)

        t.Run(fmt.Sprintf("NewHmacSHA1_test_%d", index), func(t *testing.T) {
            assertError(e.Error, "NewHmacSHA1")
            assert(test.output, e.ToHexString(), "NewHmacSHA1")
        })
    }
}
