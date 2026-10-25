"""Minimal ABI decoder for constructor arguments recovered from a verified bundle.

The deployment record of a verified contract carries the constructor arguments
exactly as they were encoded in the creation transaction, so the values are the
ones the chain actually used rather than a reconstruction.  Recovering them from
the contract's own ABI needs a decoder for the argument types a constructor
actually takes, which is a small and closed set: the head is a sequence of
32-byte words, and the types that need more than one word carry an offset to
a tail that the head points at.

Only the types that appear as constructor parameters are handled.  A type this
decoder does not know is reported as unknown instead of being guessed, because a
guessed literal would deploy a contract that differs from the verified one and
every assertion run against it would be evidence about the wrong contract.
"""

from __future__ import annotations

from typing import Any

WORD = 32
ADDRESS_SIZE = 20


class AbiDecodeError(ValueError):
    """Raised when the payload does not decode against the declared types."""


def _decode_uint(word: bytes) -> int:
    return int.from_bytes(word, "big")


def _decode_address(word: bytes) -> str:
    if len(word) != WORD:
        raise AbiDecodeError("address word has the wrong width")
    if int.from_bytes(word[:12], "big") != 0:
        raise AbiDecodeError("address word carries non-zero padding")
    return "0x" + word[12:].hex()


def _decode_bool(word: bytes) -> bool:
    value = _decode_uint(word)
    if value > 1:
        raise AbiDecodeError("bool word is neither 0 nor 1")
    return bool(value)


def _decode_bytes(word: bytes) -> bytes:
    length = _decode_uint(word)
    if length * WORD > len(word):
        raise AbiDecodeError("bytes length exceeds the enclosing word")
    return word[:length]


def _decode_string(word: bytes) -> str:
    raw = _decode_bytes(word)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AbiDecodeError("string argument is not valid UTF-8") from error


def _decode_signed(word: bytes, bits: int) -> int:
    value = _decode_uint(word)
    sign_bit = 1 << (bits - 1)
    return value - (1 << bits) if value & sign_bit else value


def _is_dynamic(element_type: str) -> bool:
    if element_type in ("bytes", "string"):
        return True
    if element_type.endswith("[]"):
        return True
    if element_type.startswith("(") and element_type.endswith(")"):
        return True
    return False


def _head_is_dynamic(element_type: str) -> bool:
    """Whether the *head slot* of a type is an offset rather than the value.

    A dynamic array occupies one head word holding the offset of its length
    word.  A static array of dynamic elements occupies one head word per
    element, each of them an offset.
    """
    if element_type.endswith("[]"):
        return True
    if element_type.startswith("(") and element_type.endswith(")"):
        return any(_is_dynamic(part) for part in _split_tuple(element_type))
    return False


def _split_tuple(element_type: str) -> list[str]:
    inner = element_type[1:-1]
    parts: list[str] = []
    depth = 0
    current = ""
    for character in inner:
        if character == "," and depth == 0:
            parts.append(current.strip())
            current = ""
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        current += character
    if current.strip():
        parts.append(current.strip())
    return parts


def _type_words(element_type: str) -> int:
    """How many head words a static type occupies."""
    if element_type.endswith("]"):
        base, _, count = element_type[:-2].rpartition("[")
        if count.startswith(""):
            pass
        if not count.isdigit():
            raise AbiDecodeError(f"unsupported array size in {element_type}")
        return int(count) * _type_words(base)
    if element_type.startswith("(") and element_type.endswith(")"):
        return sum(_type_words(part) for part in _split_tuple(element_type))
    return 1


def _decode_static(element_type: str, words: list[bytes], start: int) -> Any:
    if element_type == "address":
        return _decode_address(words[start])
    if element_type == "bool":
        return _decode_bool(words[start])
    if element_type == "string":
        return _decode_string(words[start])
    if element_type == "bytes":
        return "0x" + _decode_bytes(words[start]).hex()
    if element_type.startswith("bytes"):
        size = int(element_type[5:])
        if not 1 <= size <= 32:
            raise AbiDecodeError(f"unsupported fixed bytes width in {element_type}")
        return "0x" + b"".join(words[start:start + 1])[:size].hex()
    if element_type.startswith("uint"):
        bits = int(element_type[4:] or "256")
        if not 8 <= bits <= 256 or bits % 8:
            raise AbiDecodeError(f"unsupported integer width in {element_type}")
        return _decode_uint(words[start])
    if element_type.startswith("int"):
        bits = int(element_type[3:] or "256")
        if not 8 <= bits <= 256 or bits % 8:
            raise AbiDecodeError(f"unsupported integer width in {element_type}")
        return _decode_signed(words[start], bits)
    raise AbiDecodeError(f"unsupported type {element_type}")


def _decode_value(element_type: str, payload: bytes, words: list[bytes],
                  head_index: int) -> Any:
    if element_type.endswith("[]"):
        base = element_type[:-2]
        # An array head word is a byte offset to the length word.
        offset = _decode_uint(words[head_index]) // WORD
        if offset >= len(words):
            raise AbiDecodeError("array offset points past the argument payload")
        length = _decode_uint(words[offset])
        if length > len(words):
            raise AbiDecodeError("array length exceeds the argument payload")
        # An element is decoded by its own kind, not by assuming it is dynamic.
        # Routing every element through `_decode_dynamic_element` reported
        # `unsupported dynamic type address` for an `address[]` of one element,
        # and returned an empty list for the same type with no elements -- the
        # length zero case never reached the branch that would have refused, so
        # a decoded empty array looked like a successful decode and would have
        # been handed to a constructor as though it were the real argument.
        if base.startswith("("):
            raise AbiDecodeError("tuple array arguments are not decoded")
        if not _is_dynamic(base):
            raise AbiDecodeError(
                f"array of static type {element_type} is not decoded")
        values = []
        for index in range(length):
            values.append(_decode_dynamic_element(base, payload, words,
                                                  offset + WORD + index * WORD))
        return values
    if element_type.startswith("(") and element_type.endswith(")"):
        raise AbiDecodeError("tuple constructor arguments are not decoded")
    if element_type.endswith("]"):
        # A fixed-size array is a distinct ABI kind from a dynamic one: it sits
        # inline in the head rather than behind an offset, so there is no single
        # branch here that could decode it correctly.  Raising the decoder's own
        # error keeps the failure in the one exception type callers already
        # handle, instead of surfacing as an unrelated `ValueError` from a string
        # parse further down.
        raise AbiDecodeError(
            f"fixed-size array argument {element_type} is not decoded")
    if _is_dynamic(element_type):
        # The head word holds a byte offset into the payload, not a word index.
        offset = _decode_uint(words[head_index])
        return _decode_dynamic_element(element_type, payload, words, offset // WORD)
    return _decode_static(element_type, words, head_index)


def _decode_dynamic_element(element_type: str, payload: bytes, words: list[bytes],
                            tail_word: int) -> Any:
    if element_type == "string":
        length = _decode_uint(words[tail_word])
        raw = payload[tail_word * WORD + WORD: tail_word * WORD + WORD + length]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AbiDecodeError("string argument is not valid UTF-8") from error
    if element_type == "bytes":
        length = _decode_uint(words[tail_word])
        raw = payload[tail_word * WORD + WORD: tail_word * WORD + WORD + length]
        return "0x" + raw.hex()
    raise AbiDecodeError(f"unsupported dynamic type {element_type}")


def decode_constructor_arguments(payload: str | bytes, inputs: list[dict[str, Any]]) -> list[Any]:
    """Decode a creation-transaction argument blob against a constructor ABI.

    ``inputs`` are the ``inputs`` entries of the contract's own ``constructor``
    ABI item, in declaration order.  The returned list is in the same order, so
    it can be handed straight to a caller that builds a ``new Contract(...)``
    expression.
    """
    if isinstance(payload, str):
        text = payload[2:] if payload.startswith("0x") else payload
        if len(text) % 2:
            raise AbiDecodeError("argument payload has an odd number of hex digits")
        try:
            raw = bytes.fromhex(text)
        except ValueError as error:
            raise AbiDecodeError("argument payload is not hex") from error
    else:
        raw = payload
    if not inputs:
        return []
    if not raw:
        raise AbiDecodeError("argument payload is empty but the constructor declares parameters")
    if len(raw) % WORD:
        raise AbiDecodeError("argument payload is not a whole number of words")
    words = [raw[index:index + WORD] for index in range(0, len(raw), WORD)]
    # The head holds one word per declared parameter, so fewer words than
    # parameters cannot be a complete encoding.  Without this the loop below
    # ran off the end of `words` and surfaced as an `IndexError`, which a
    # caller handling only `AbiDecodeError` would not have caught.
    if len(words) < len(inputs):
        raise AbiDecodeError(
            f"argument payload has {len(words)} words for {len(inputs)} parameters")
    # When no parameter is dynamic the encoding is exactly one word per
    # parameter, so a longer payload is not this constructor's arguments.  It
    # was previously decoded from its first words and the rest ignored, which
    # turns a payload that was not trimmed correctly -- the start of the
    # creation code, say -- into values that look like a real reading.  A
    # dynamic parameter has a tail whose length the types do not fix, so the
    # surplus check applies to the all-static case only.
    if not any(_is_dynamic(str(item.get("type") or "")) for item in inputs):
        if len(words) != len(inputs):
            raise AbiDecodeError(
                f"argument payload has {len(words)} words but the static "
                f"parameters occupy {len(inputs)}")
    values: list[Any] = []
    head_index = 0
    for item in inputs:
        element_type = str(item.get("type") or "")
        if not element_type:
            raise AbiDecodeError("constructor input has no type")
        values.append(_decode_value(element_type, raw, words, head_index))
        head_index += 1
    return values
