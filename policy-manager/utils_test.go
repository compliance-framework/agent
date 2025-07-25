package policy_manager

import (
	"gotest.tools/v3/assert"
	"testing"
)

func TestMergeMaps(t *testing.T) {
	t.Run("StringMaps", func(t *testing.T) {
		maps := []map[string]string{
			{
				"key1": "value1",
			},
			{
				"key2": "value2",
			},
		}
		expected := map[string]string{
			"key1": "value1",
			"key2": "value2",
		}
		output := MergeMaps(maps...)
		assert.DeepEqual(t, output, expected)
	})

	t.Run("IntKeyMaps", func(t *testing.T) {
		maps := []map[int]string{
			{
				0: "value1",
			},
			{
				1: "value2",
			},
		}
		expected := map[int]string{
			0: "value1",
			1: "value2",
		}
		output := MergeMaps(maps...)
		assert.DeepEqual(t, output, expected)
	})

	t.Run("StructMaps", func(t *testing.T) {
		maps := []map[int]struct{ Some string }{
			{
				0: {
					Some: "foo",
				},
			},
			{
				1: {
					Some: "bar",
				},
			},
		}
		expected := map[int]struct{ Some string }{
			0: {
				Some: "foo",
			},
			1: {
				Some: "bar",
			},
		}
		output := MergeMaps(maps...)
		assert.DeepEqual(t, output, expected)
	})

	t.Run("Many maps", func(t *testing.T) {
		assert.DeepEqual(t, MergeMaps(
			map[string]string{"foo": "bar"},
			map[string]string{"bar": "baz"},
			map[string]string{"baz": "yaz"},
		), map[string]string{
			"foo": "bar",
			"bar": "baz",
			"baz": "yaz",
		})
	})
}

func TestPointer(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		output := Pointer("foobar")
		assert.Equal(t, "foobar", *output)
	})
	t.Run("Int", func(t *testing.T) {
		output := Pointer(123)
		assert.Equal(t, 123, *output)
	})
	t.Run("List", func(t *testing.T) {
		output := Pointer([]string{"foo", "bar"})
		assert.DeepEqual(t, []string{"foo", "bar"}, *output)
	})
}

func TestFirstOf(t *testing.T) {
	t.Run("String", func(t *testing.T) {
		firstFilled := FirstOf(Pointer("first"), Pointer("second"))
		assert.Equal(t, "first", *firstFilled)

		secondFilled := FirstOf(nil, Pointer("second"))
		assert.Equal(t, "second", *secondFilled)
	})
}
