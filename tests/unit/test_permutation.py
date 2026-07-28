import numpy as np

from stagy.permutation import keyed_indices


def test_deterministic() -> None:
    a = keyed_indices(1000, b"seed")
    b = keyed_indices(1000, b"seed")
    assert np.array_equal(a, b)
    assert sorted(a.tolist()) == list(range(1000))


def test_seed_changes_order() -> None:
    assert not np.array_equal(keyed_indices(1000, b"a"), keyed_indices(1000, b"b"))
