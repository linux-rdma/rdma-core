#!/usr/bin/env python3
# SPDX-License-Identifier: Linux-OpenIB
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
"""Unit tests for NVCX_Topo and its nested NIC / Board types.

Tests import rdma_topo via load_rdma_topo() (which strips the bare main()
call) and use lightweight mock PCIDevice objects so no sysfs or dump file
is needed.
"""
from __future__ import annotations

import sys
import types

from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import MagicMock

try:
    import pytest
except ImportError:
    print("Missing dependency: pytest", file=sys.stderr)
    print("Install with: pip3 install pytest", file=sys.stderr)
    sys.exit(1)

HERE = Path(__file__).resolve().parent
RDMA_TOPO = HERE / "rdma_topo"


def _strip_trailing_main_call(src: str) -> str:
    """rdma_topo ends with bare main(); skip it so test import does not run CLI."""
    lines = src.splitlines()
    i = len(lines) - 1
    while i >= 0 and lines[i].strip() == "":
        i -= 1
    if i < 0:
        return src
    if lines[i].split("#", 1)[0].strip() == "main()":
        return "\n".join(lines[:i]) + ("\n" if i else "")
    return src


def load_rdma_topo():
    raw = RDMA_TOPO.read_text(encoding="utf-8")
    code_s = _strip_trailing_main_call(raw)
    mod = types.ModuleType("rdma_topo")
    mod.__file__ = str(RDMA_TOPO)
    mod.__name__ = "rdma_topo"
    mod.__package__ = ""
    sys.modules["rdma_topo"] = mod
    exec(compile(code_s, str(RDMA_TOPO), "exec"), mod.__dict__)
    return mod


load_rdma_topo()

from rdma_topo import PCIBDF, NVCX_Topo, TopoUnexpectedError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_dev(
    bdf_str: str,
    vpd_sn: Optional[str] = None,
    parent=None,
    has_ats: bool = False,
    subsystems: Optional[Dict] = None,
) -> MagicMock:
    """Return a mock PCIDevice for use with NVCX_Topo code."""
    dev = MagicMock(name=f"PCIDevice({bdf_str})")
    seg, bus, rest = bdf_str.split(":")
    d, func = rest.split(".")
    dev.bdf = PCIBDF(seg, bus, d, func)
    dev.vpd_sn = vpd_sn
    dev.parent = parent
    dev.has_ats = has_ats
    dev.get_subsystems.return_value = subsystems or {}
    return dev


def make_parent(bdf_str: str) -> MagicMock:
    """Return a mock parent PCIDevice (used as NIC.parent)."""
    p = MagicMock(name=f"ParentDevice({bdf_str})")
    seg, bus, rest = bdf_str.split(":")
    d, func = rest.split(".")
    p.bdf = PCIBDF(seg, bus, d, func)
    return p


def make_nic(
    pf_bdfs: List[str],
    parent_bdf: Optional[str] = None,
    vpd_sn: Optional[str] = None,
    has_ats: bool = False,
    subsystems: Optional[Dict] = None,
) -> NVCX_Topo.NIC:
    """Construct a NVCX_Topo.NIC from mock PCIDevices."""
    parent = make_parent(parent_bdf) if parent_bdf else None
    devs = [
        make_dev(
            bdf, vpd_sn=vpd_sn, parent=parent, has_ats=has_ats, subsystems=subsystems
        )
        for bdf in pf_bdfs
    ]
    return NVCX_Topo.NIC(set(devs))


# ---------------------------------------------------------------------------
# NVCX_Topo.NIC — constructor
# ---------------------------------------------------------------------------


class TestNVCX_Topo_NIC_Constructor:
    def test_single_pf_no_parent(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf=None, vpd_sn=None)
        assert nic.parent is None
        assert nic.vpd_sn is None
        assert len(nic.pfs) == 1

    def test_single_pf_with_parent_and_sn(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        assert str(nic.parent.bdf) == "0000:00:00.0"
        assert nic.vpd_sn == "SN123"

    def test_multi_pf_same_parent_same_sn(self):
        nic = make_nic(
            ["0000:00:01.0", "0000:00:02.0"],
            parent_bdf="0000:00:00.0",
            vpd_sn="SN123",
        )
        assert len(nic.pfs) == 2

    def test_multi_pf_different_parent_raises(self):
        parent_a = make_parent("0000:00:00.0")
        parent_b = make_parent("0000:00:10.0")
        dev_a = make_dev("0000:00:01.0", parent=parent_a, vpd_sn="SN")
        dev_b = make_dev("0000:00:02.0", parent=parent_b, vpd_sn="SN")
        with pytest.raises(TopoUnexpectedError, match="same parent"):
            NVCX_Topo.NIC({dev_a, dev_b})

    def test_multi_pf_different_sn_raises(self):
        parent = make_parent("0000:00:00.0")
        dev_a = make_dev("0000:00:01.0", parent=parent, vpd_sn="SN1")
        dev_b = make_dev("0000:00:02.0", parent=parent, vpd_sn="SN2")
        with pytest.raises(TopoUnexpectedError, match="same VPD SN"):
            NVCX_Topo.NIC({dev_a, dev_b})


# ---------------------------------------------------------------------------
# NVCX_Topo.NIC — primary_pf
# ---------------------------------------------------------------------------


class TestNVCX_Topo_NIC_PrimaryPf:
    def test_multi_pf_returns_min_bdf(self):
        parent = make_parent("0000:00:00.0")
        dev_lo = make_dev("0000:00:01.0", parent=parent, vpd_sn="SN")
        dev_hi = make_dev("0000:00:02.0", parent=parent, vpd_sn="SN")
        nic = NVCX_Topo.NIC({dev_lo, dev_hi})
        assert nic.primary_pf is dev_lo


# ---------------------------------------------------------------------------
# NVCX_Topo.NIC — to_dict
# ---------------------------------------------------------------------------


class TestNVCX_Topo_NIC_ToDict:
    def test_has_parent_bdf(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        assert nic.to_dict()["parent_bdf"] == "0000:00:00.0"

    def test_no_parent_gives_unknown(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf=None, vpd_sn=None)
        assert nic.to_dict()["parent_bdf"] == "UNKNOWN"


    def test_ats_taken_from_min_bdf_pf(self):
        parent = make_parent("0000:00:00.0")
        dev_lo = make_dev("0000:00:01.0", parent=parent, vpd_sn="SN", has_ats=False)
        dev_hi = make_dev("0000:00:02.0", parent=parent, vpd_sn="SN", has_ats=True)
        nic = NVCX_Topo.NIC({dev_lo, dev_hi})
        assert nic.to_dict()["ats"] == False
        nic = NVCX_Topo.NIC({dev_hi, dev_lo})
        assert nic.to_dict()["ats"] == False


# ---------------------------------------------------------------------------
# NVCX_Topo.NIC — __str__
# ---------------------------------------------------------------------------


class TestNVCX_Topo_NIC_Str:
    def test_single_pf_starts_with_nic_parent_header(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        assert str(nic).startswith("RDMA NIC Parent=0000:00:00.0")

    def test_single_pf_no_parent_shows_unknown(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf=None, vpd_sn=None)
        assert str(nic).startswith("RDMA NIC Parent=UNKNOWN")

    def test_single_pf_ats_no(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        assert "NIC ATS: no" in str(nic)

    def test_single_pf_ats_yes(self):
        nic = make_nic(
            ["0000:00:01.0"],
            parent_bdf="0000:00:00.0",
            vpd_sn="SN123",
            has_ats=True,
        )
        assert "NIC ATS: yes" in str(nic)

    def test_no_trailing_newline(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        assert not str(nic).endswith("\n")

    def test_single_pf_with_infiniband(self):
        nic = make_nic(
            ["0000:00:01.0"],
            parent_bdf="0000:00:00.0",
            vpd_sn="SN123",
            subsystems={"infiniband": {"mlx5_0"}},
        )
        assert "RDMA device: mlx5_0" in str(nic)

    def test_single_pf_with_net(self):
        nic = make_nic(
            ["0000:00:01.0"],
            parent_bdf="0000:00:00.0",
            vpd_sn="SN123",
            subsystems={"net": {"eth0"}},
        )
        assert "Net device: eth0" in str(nic)

    def test_multi_pf_shows_sorted_pci_device_list(self):
        nic = make_nic(
            ["0000:00:02.0", "0000:00:01.0"],
            parent_bdf="0000:00:00.0",
            vpd_sn="SN123",
        )
        assert "NIC PCI devices: 0000:00:01.0, 0000:00:02.0" in str(nic)

    def test_multi_pf_subsystems_merged(self):
        parent = make_parent("0000:00:00.0")
        dev1 = make_dev(
            "0000:00:01.0",
            parent=parent,
            vpd_sn="SN",
            subsystems={"infiniband": {"mlx5_0"}, "net": {"eth0"}},
        )
        dev2 = make_dev(
            "0000:00:02.0",
            parent=parent,
            vpd_sn="SN",
            subsystems={"infiniband": {"mlx5_1"}, "net": {"eth1"}},
        )
        nic = NVCX_Topo.NIC({dev1, dev2})
        result = str(nic)
        assert "RDMA devices: mlx5_0, mlx5_1" in result
        assert "Net devices: eth0, eth1" in result


# ---------------------------------------------------------------------------
# NVCX_Topo.Board — constructor
# ---------------------------------------------------------------------------


class TestNVCX_Topo_Board_Constructor:
    def test_single_nic_sn_stored(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        board = NVCX_Topo.Board({nic})
        assert board.sn == "SN123"
        assert nic in board.nics

    def test_multi_nic_same_sn(self):
        nic_a = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        nic_b = make_nic(["0000:00:11.0"], parent_bdf="0000:00:10.0", vpd_sn="SN123")
        board = NVCX_Topo.Board({nic_a, nic_b})
        assert len(board.nics) == 2
        assert board.sn == "SN123"

    def test_multi_nic_different_sn_raises(self):
        nic_a = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN1")
        nic_b = make_nic(["0000:00:11.0"], parent_bdf="0000:00:10.0", vpd_sn="SN2")
        with pytest.raises(TopoUnexpectedError, match="same VPD SN"):
            NVCX_Topo.Board({nic_a, nic_b})


# ---------------------------------------------------------------------------
# NVCX_Topo.Board — to_dict
# ---------------------------------------------------------------------------


class TestNVCX_Topo_Board_ToDict:
    def test_has_board_sn(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        board = NVCX_Topo.Board({nic})
        assert board.to_dict()["board_sn"] == "SN123"

    def test_none_sn_gives_unknown(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf=None, vpd_sn=None)
        board = NVCX_Topo.Board({nic})
        assert board.to_dict()["board_sn"] == "UNKNOWN"

    def test_nics_list_length(self):
        nic_a = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        nic_b = make_nic(["0000:00:11.0"], parent_bdf="0000:00:10.0", vpd_sn="SN123")
        board = NVCX_Topo.Board({nic_a, nic_b})
        assert len(board.to_dict()["nics"]) == 2

    def test_nics_list_contains_nic_dicts(self):
        nic = make_nic(
            ["0000:00:01.0", "0000:00:02.0"],
            parent_bdf="0000:00:00.0",
            vpd_sn="SN123",
        )
        board = NVCX_Topo.Board({nic})
        nic_dict = board.to_dict()["nics"][0]
        assert nic_dict == nic.to_dict()


# ---------------------------------------------------------------------------
# NVCX_Topo.Board — __str__
# ---------------------------------------------------------------------------


class TestNVCX_Topo_Board_Str:
    def test_single_nic_starts_with_board_header(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        board = NVCX_Topo.Board({nic})
        assert str(board).startswith("RDMA NIC Board=SN123")

    def test_none_sn_shows_unknown(self):
        nic = make_nic(["0000:00:01.0"], parent_bdf=None, vpd_sn=None)
        board = NVCX_Topo.Board({nic})
        assert str(board).startswith("RDMA NIC Board=UNKNOWN")

    def test_multi_nic_includes_nic_parent_headers(self):
        nic_a = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        nic_b = make_nic(["0000:00:11.0"], parent_bdf="0000:00:10.0", vpd_sn="SN123")
        board = NVCX_Topo.Board({nic_a, nic_b})
        result = str(board)
        assert "RDMA NIC Parent=0000:00:00.0" in result
        assert "RDMA NIC Parent=0000:00:10.0" in result

    def test_multi_nic_nic_body_indented(self):
        nic_a = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        nic_b = make_nic(["0000:00:11.0"], parent_bdf="0000:00:10.0", vpd_sn="SN123")
        board = NVCX_Topo.Board({nic_a, nic_b})
        result = str(board)
        assert "\t\tNIC ATS: no" in result

    def test_multi_nic_no_trailing_newline(self):
        nic_a = make_nic(["0000:00:01.0"], parent_bdf="0000:00:00.0", vpd_sn="SN123")
        nic_b = make_nic(["0000:00:11.0"], parent_bdf="0000:00:10.0", vpd_sn="SN123")
        board = NVCX_Topo.Board({nic_a, nic_b})
        assert not str(board).endswith("\n")


# ---------------------------------------------------------------------------
# NVCX_Topo — constructor
# ---------------------------------------------------------------------------


class TestNVCX_Topo_Constructor:
    def test_single_pf_with_parent_and_sn_yields_one_board(self):
        parent = make_parent("0000:00:00.0")
        dev = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent)
        topo = NVCX_Topo({dev})
        assert len(topo.boards) == 1

    def test_two_pfs_same_parent_same_sn_one_nic_one_board(self):
        parent = make_parent("0000:00:00.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent)
        dev2 = make_dev("0000:00:02.0", vpd_sn="SN123", parent=parent)
        topo = NVCX_Topo({dev1, dev2})
        assert len(topo.boards) == 1
        assert len(topo.boards[0].nics) == 1
        assert len(topo.boards[0].nics[0].pfs) == 2

    def test_two_pfs_different_parent_same_sn_two_nics_one_board(self):
        parent_a = make_parent("0000:00:00.0")
        parent_b = make_parent("0000:00:10.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent_a)
        dev2 = make_dev("0000:00:11.0", vpd_sn="SN123", parent=parent_b)
        topo = NVCX_Topo({dev1, dev2})
        assert len(topo.boards) == 1
        assert len(topo.boards[0].nics) == 2

    def test_two_pfs_different_sn_two_boards(self):
        parent_a = make_parent("0000:00:00.0")
        parent_b = make_parent("0000:00:10.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN1", parent=parent_a)
        dev2 = make_dev("0000:00:11.0", vpd_sn="SN2", parent=parent_b)
        topo = NVCX_Topo({dev1, dev2})
        assert len(topo.boards) == 2


# ---------------------------------------------------------------------------
# NVCX_Topo — pfs / primary_pf
# ---------------------------------------------------------------------------


class TestNVCX_Topo_Pfs:
    def test_pfs_returns_all_devs(self):
        parent = make_parent("0000:00:00.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent)
        dev2 = make_dev("0000:00:02.0", vpd_sn="SN123", parent=parent)
        topo = NVCX_Topo({dev1, dev2})
        assert topo.pfs == {dev1, dev2}

    def test_primary_pf_is_min_bdf(self):
        parent = make_parent("0000:00:00.0")
        dev_lo = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent)
        dev_hi = make_dev("0000:00:02.0", vpd_sn="SN123", parent=parent)
        topo = NVCX_Topo({dev_lo, dev_hi})
        assert topo.primary_pf is dev_lo

    def test_primary_pf_across_boards(self):
        parent_a = make_parent("0000:00:00.0")
        parent_b = make_parent("0000:00:10.0")
        dev_lo = make_dev("0000:00:01.0", vpd_sn="SN1", parent=parent_a)
        dev_hi = make_dev("0000:00:11.0", vpd_sn="SN2", parent=parent_b)
        topo = NVCX_Topo({dev_lo, dev_hi})
        assert topo.primary_pf is dev_lo


# ---------------------------------------------------------------------------
# NVCX_Topo — to_dict
# ---------------------------------------------------------------------------


class TestNVCX_Topo_ToDict:
    def test_single_pf_returns_flat_dict(self):
        parent = make_parent("0000:00:00.0")
        dev = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent)
        topo = NVCX_Topo({dev})
        result = topo.to_dict()
        assert result["rdma_nic_pf_bdf"] == "0000:00:01.0"
        assert result["rdma_nic_ats"] == False

    def test_single_board_multi_pf_nic(self):
        parent = make_parent("0000:00:00.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent)
        dev2 = make_dev("0000:00:02.0", vpd_sn="SN123", parent=parent)
        topo = NVCX_Topo({dev1, dev2})
        result = topo.to_dict()
        boards = result["rdma_nic_boards"]
        assert len(boards) == 1
        board = boards[0]
        assert board["board_sn"] == "SN123"
        assert len(board["nics"]) == 1
        nic_dict = board["nics"][0]
        assert nic_dict["parent_bdf"] == "0000:00:00.0"
        assert "ats" in nic_dict
        assert nic_dict["pf_bdfs"] == ["0000:00:01.0", "0000:00:02.0"]

    def test_multi_board_multi_pf_nics(self):
        parent_a = make_parent("0000:00:00.0")
        parent_b = make_parent("0000:00:10.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN1", parent=parent_a)
        dev2 = make_dev("0000:00:02.0", vpd_sn="SN1", parent=parent_a)
        dev3 = make_dev("0000:00:11.0", vpd_sn="SN2", parent=parent_b)
        dev4 = make_dev("0000:00:12.0", vpd_sn="SN2", parent=parent_b)
        topo = NVCX_Topo({dev1, dev2, dev3, dev4})
        result = topo.to_dict()
        assert len(result["rdma_nic_boards"]) == 2

    def test_single_board_multi_nic_multi_pf(self):
        parent_a = make_parent("0000:00:00.0")
        parent_b = make_parent("0000:00:10.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent_a)
        dev2 = make_dev("0000:00:02.0", vpd_sn="SN123", parent=parent_a)
        dev3 = make_dev("0000:00:11.0", vpd_sn="SN123", parent=parent_b)
        dev4 = make_dev("0000:00:12.0", vpd_sn="SN123", parent=parent_b)
        topo = NVCX_Topo({dev1, dev2, dev3, dev4})
        result = topo.to_dict()
        boards = result["rdma_nic_boards"]
        assert len(boards) == 1
        assert len(boards[0]["nics"]) == 2

    def test_boards_sorted_by_sn_in_to_dict(self):
        parent_a = make_parent("0000:00:00.0")
        parent_b = make_parent("0000:00:10.0")
        dev_b = make_dev("0000:00:11.0", vpd_sn="SN_B", parent=parent_b)
        dev_a = make_dev("0000:00:01.0", vpd_sn="SN_A", parent=parent_a)
        topo = NVCX_Topo({dev_a, dev_b})
        boards = topo.to_dict()["rdma_nic_boards"]
        assert boards[0]["board_sn"] == "SN_A"
        assert boards[1]["board_sn"] == "SN_B"


# ---------------------------------------------------------------------------
# NVCX_Topo — topo_str_key
# ---------------------------------------------------------------------------


class TestNVCX_Topo_TopoStrKey:
    def test_single_pf_returns_nic_bdf(self):
        parent = make_parent("0000:00:00.0")
        dev = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent)
        topo = NVCX_Topo({dev})
        assert topo.topo_str_key() == "RDMA NIC=0000:00:01.0"

    def test_multi_pf_returns_empty(self):
        parent = make_parent("0000:00:00.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent)
        dev2 = make_dev("0000:00:02.0", vpd_sn="SN123", parent=parent)
        topo = NVCX_Topo({dev1, dev2})
        assert topo.topo_str_key() == ""


# ---------------------------------------------------------------------------
# NVCX_Topo — topo_str
# ---------------------------------------------------------------------------


class TestNVCX_Topo_TopoStr:
    def test_single_pf_contains_ats(self):
        parent = make_parent("0000:00:00.0")
        dev = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent)
        topo = NVCX_Topo({dev})
        result = topo.topo_str()
        assert "NIC ATS: no" in result
        assert not result.endswith("\n")

    def test_single_board_single_nic_multi_pf(self):
        parent = make_parent("0000:00:00.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent)
        dev2 = make_dev("0000:00:02.0", vpd_sn="SN123", parent=parent)
        topo = NVCX_Topo({dev1, dev2})
        result = topo.topo_str()
        assert "NIC ATS: no" in result
        assert "NIC PCI devices: 0000:00:01.0, 0000:00:02.0" in result

    def test_single_board_multi_nic_has_nic_parent_headers(self):
        parent_a = make_parent("0000:00:00.0")
        parent_b = make_parent("0000:00:10.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN123", parent=parent_a)
        dev2 = make_dev("0000:00:11.0", vpd_sn="SN123", parent=parent_b)
        topo = NVCX_Topo({dev1, dev2})
        result = topo.topo_str()
        assert "RDMA NIC Parent=0000:00:00.0" in result
        assert "RDMA NIC Parent=0000:00:10.0" in result

    def test_multi_board_has_nic_parent_headers(self):
        parent_a = make_parent("0000:00:00.0")
        parent_b = make_parent("0000:00:10.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN1", parent=parent_a)
        dev2 = make_dev("0000:00:11.0", vpd_sn="SN2", parent=parent_b)
        topo = NVCX_Topo({dev1, dev2})
        result = topo.topo_str()
        assert "RDMA NIC Parent=0000:00:00.0" in result
        assert "RDMA NIC Parent=0000:00:10.0" in result

    def test_multi_board_body_indented(self):
        parent_a = make_parent("0000:00:00.0")
        parent_b = make_parent("0000:00:10.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN1", parent=parent_a)
        dev2 = make_dev("0000:00:11.0", vpd_sn="SN2", parent=parent_b)
        topo = NVCX_Topo({dev1, dev2})
        result = topo.topo_str()
        assert "\t\t\tNIC ATS: no" in result

    def test_multi_board_no_trailing_newline(self):
        parent_a = make_parent("0000:00:00.0")
        parent_b = make_parent("0000:00:10.0")
        dev1 = make_dev("0000:00:01.0", vpd_sn="SN1", parent=parent_a)
        dev2 = make_dev("0000:00:11.0", vpd_sn="SN2", parent=parent_b)
        topo = NVCX_Topo({dev1, dev2})
        assert not topo.topo_str().endswith("\n")


# ---------------------------------------------------------------------------
# NVCX_Topo — board / NIC ordering
# ---------------------------------------------------------------------------


class TestNVCX_Topo_Ordering:
    def test_boards_sorted_by_sn(self):
        parent_a = make_parent("0000:00:00.0")
        parent_b = make_parent("0000:00:10.0")
        dev_b = make_dev("0000:00:11.0", vpd_sn="SN_B", parent=parent_b)
        dev_a = make_dev("0000:00:01.0", vpd_sn="SN_A", parent=parent_a)
        topo = NVCX_Topo({dev_a, dev_b})
        assert topo.boards[0].sn == "SN_A"
        assert topo.boards[1].sn == "SN_B"

    def test_board_nics_sorted_by_parent_bdf(self):
        parent_lo = make_parent("0000:00:00.0")
        parent_hi = make_parent("0000:00:10.0")
        dev_hi = make_dev("0000:00:11.0", vpd_sn="SN", parent=parent_hi)
        dev_lo = make_dev("0000:00:01.0", vpd_sn="SN", parent=parent_lo)
        topo = NVCX_Topo({dev_lo, dev_hi})
        board = topo.boards[0]
        assert str(board.nics[0].parent.bdf) == "0000:00:00.0"
        assert str(board.nics[1].parent.bdf) == "0000:00:10.0"

    def test_board_nic_without_parent_sorts_after_nic_with_parent(self):
        parent = make_parent("0000:00:00.0")
        dev_parented = make_dev("0000:00:01.0", vpd_sn="SN", parent=parent)
        dev_orphan = make_dev("0000:00:02.0", vpd_sn="SN", parent=None)
        nic_parented = NVCX_Topo.NIC({dev_parented})
        nic_orphan = NVCX_Topo.NIC({dev_orphan})
        board = NVCX_Topo.Board({nic_parented, nic_orphan})
        assert board.nics[0] is nic_parented
        assert board.nics[1] is nic_orphan
