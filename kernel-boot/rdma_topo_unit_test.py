#!/usr/bin/env python3
# SPDX-License-Identifier: Linux-OpenIB
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
"""Unit tests for NVCX_Topo and its nested NIC / Board types.

Tests import rdma_topo via load_rdma_topo() (which strips the bare main()
call) and use lightweight mock PCIDevice objects so no sysfs or dump file
is needed.
"""
from __future__ import annotations

import contextlib
import io
import os
import shlex
import sys
import tempfile
import types

from pathlib import Path
from typing import Dict, List, Optional
from unittest import mock
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

import rdma_topo

from rdma_topo import (
    PCIBDF,
    GrubbyBackend,
    NVCX_Topo,
    TopoUnexpectedError,
    UpdateGrubBackend,
    acs_cmdline_subopt,
    grub_dropin_content,
    merge_pci_param,
    parse_grubby_info,
    select_cmdline_backend,
    split_cmdline,
    update_file,
)

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


# ---------------------------------------------------------------------------
# update_file
# ---------------------------------------------------------------------------


class TestUpdateFile:
    def test_creates_file_and_returns_true(self):
        with tempfile.TemporaryDirectory() as d:
            fn = os.path.join(d, "cfg")
            assert update_file(fn, "content\n") is True
            with open(fn, "rt") as F:
                assert F.read() == "content\n"

    def test_unchanged_content_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            fn = os.path.join(d, "cfg")
            update_file(fn, "content\n")
            assert update_file(fn, "content\n") is False

    def test_changed_content_returns_true(self):
        with tempfile.TemporaryDirectory() as d:
            fn = os.path.join(d, "cfg")
            update_file(fn, "old\n")
            assert update_file(fn, "new\n") is True
            with open(fn, "rt") as F:
                assert F.read() == "new\n"


# ---------------------------------------------------------------------------
# grub_dropin_content
# ---------------------------------------------------------------------------

ACS_ARG = "xx110x1@0000:01:00.0;xx101x1@0000:02:00.0"


class TestGrubDropinContent:
    def content(self, acs_arg: str = ACS_ARG, argv0: str = "/usr/sbin/rdma_topo") -> str:
        with mock.patch.object(sys, "argv", [argv0]):
            return grub_dropin_content(acs_arg)

    def test_is_two_lines(self):
        assert len(self.content().splitlines()) == 2

    def test_exact_content(self):
        expected = [
            "# Generated by /usr/sbin/rdma_topo do not change. ACS settings for RDMA GPU Direct",
            f'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX pci=config_acs=\\"{ACS_ARG}\\""',
        ]
        assert self.content() == "\n".join(expected)

    def test_value_stays_quoted(self):
        # ';' separates commands in the grub config language. Without the
        # quotes grub truncates the value and every device after the first is
        # silently left unconfigured.
        assert f'pci=config_acs=\\"{ACS_ARG}\\"' in self.content()


# ---------------------------------------------------------------------------
# UpdateGrubBackend
# ---------------------------------------------------------------------------


class TestUpdateGrubBackend:
    def test_dry_run_prints_content_and_changes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "grub.d", "config-acs.cfg")
            buf = io.StringIO()
            with mock.patch.object(rdma_topo.subprocess, "check_call") as check_call:
                with contextlib.redirect_stdout(buf):
                    UpdateGrubBackend(out).apply(ACS_ARG, dry_run=True)
            assert check_call.call_count == 0
            assert not os.path.exists(out)
            assert buf.getvalue() == grub_dropin_content(ACS_ARG) + "\n"

    def test_apply_writes_file_and_runs_update_grub(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "grub.d", "config-acs.cfg")
            with mock.patch.object(rdma_topo.subprocess, "check_call") as check_call:
                UpdateGrubBackend(out).apply(ACS_ARG, dry_run=False)
                assert check_call.call_args_list == [mock.call(["update-grub"])]
            with open(out, "rt") as F:
                assert F.read() == grub_dropin_content(ACS_ARG) + "\n"

    def test_apply_unchanged_does_not_rerun_update_grub(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "grub.d", "config-acs.cfg")
            backend = UpdateGrubBackend(out)
            with mock.patch.object(rdma_topo.subprocess, "check_call"):
                backend.apply(ACS_ARG, dry_run=False)
            with mock.patch.object(rdma_topo.subprocess, "check_call") as check_call:
                backend.apply(ACS_ARG, dry_run=False)
                assert check_call.call_count == 0

    def test_remove_missing_file_returns_false(self):
        with tempfile.TemporaryDirectory() as d:
            backend = UpdateGrubBackend(os.path.join(d, "config-acs.cfg"))
            assert backend.remove(dry_run=False) is False

    def test_remove_unlinks_and_returns_true(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "config-acs.cfg")
            with open(out, "wt") as F:
                F.write("stale\n")
            assert UpdateGrubBackend(out).remove(dry_run=False) is True
            assert not os.path.exists(out)

    def test_remove_dry_run_keeps_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "config-acs.cfg")
            with open(out, "wt") as F:
                F.write("stale\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                assert UpdateGrubBackend(out).remove(dry_run=True) is True
            assert os.path.exists(out)
            assert buf.getvalue() == f"rm {out}\n"


# ---------------------------------------------------------------------------
# acs_cmdline_subopt / split_cmdline / parse_grubby_info / merge_pci_param
# ---------------------------------------------------------------------------


class TestAcsCmdlineSubopt:
    def test_exact_value(self):
        assert acs_cmdline_subopt(ACS_ARG) == f"config_acs='{ACS_ARG}'"

    def test_single_quoted(self):
        # Not unquoted: grub truncates the value at the first ';' and every
        # device after the first is silently left unconfigured.
        # Not double quoted: grubby copies the value into the double quoted
        # GRUB_CMDLINE_LINUX of /etc/default/grub, and nested double quotes
        # end that assignment early, corrupting the file.
        subopt = acs_cmdline_subopt(ACS_ARG)
        assert subopt.startswith("config_acs='")
        assert subopt.endswith("'")
        assert '"' not in subopt


class TestSplitCmdline:
    def test_plain(self):
        assert split_cmdline("ro quiet") == ["ro", "quiet"]

    def test_keeps_single_quoted_section_together(self):
        assert split_cmdline("ro pci=config_acs='a;b' quiet") == [
            "ro",
            "pci=config_acs='a;b'",
            "quiet",
        ]

    def test_keeps_double_quoted_section_together(self):
        assert split_cmdline('ro pci=config_acs="a;b" quiet') == [
            "ro",
            'pci=config_acs="a;b"',
            "quiet",
        ]

    def test_quoted_whitespace_stays_in_one_token(self):
        assert split_cmdline("ro x='a b' quiet") == ["ro", "x='a b'", "quiet"]

    def test_empty(self):
        assert split_cmdline("") == []

    def test_repeated_whitespace(self):
        assert split_cmdline("  ro   quiet ") == ["ro", "quiet"]


GRUBBY_INFO = """index=0
kernel="/boot/vmlinuz-6.12.0-211.2.1.el10_2.x86_64"
args="ro crashkernel=1G-4G:192M rhgb quiet $tuned_params"
root="/dev/mapper/rhel-root"
initrd="/boot/initramfs-6.12.0-211.2.1.el10_2.x86_64.img"
title="Red Hat Enterprise Linux (6.12.0-211.2.1.el10_2.x86_64) 10.2"
id="61cf8d21-0"
index=1
kernel="/boot/vmlinuz-0-rescue"
args="ro quiet"
root="/dev/mapper/rhel-root"
initrd="/boot/initramfs-0-rescue.img"
title="Red Hat Enterprise Linux (0-rescue) 10.2"
id="61cf8d21-1"
"""


class TestParseGrubbyInfo:
    def test_entry_count(self):
        assert len(parse_grubby_info(GRUBBY_INFO)) == 2

    def test_strips_quotes(self):
        entry = parse_grubby_info(GRUBBY_INFO)[0]
        assert entry["kernel"] == "/boot/vmlinuz-6.12.0-211.2.1.el10_2.x86_64"
        assert entry["args"] == "ro crashkernel=1G-4G:192M rhgb quiet $tuned_params"

    def test_second_entry(self):
        assert parse_grubby_info(GRUBBY_INFO)[1]["kernel"] == "/boot/vmlinuz-0-rescue"

    def test_without_index_lines(self):
        out = 'kernel="/boot/vmlinuz-a"\nargs="ro"\nkernel="/boot/vmlinuz-b"\nargs="quiet"\n'
        entries = parse_grubby_info(out)
        assert [e["kernel"] for e in entries] == ["/boot/vmlinuz-a", "/boot/vmlinuz-b"]
        assert [e["args"] for e in entries] == ["ro", "quiet"]

    def test_empty(self):
        assert parse_grubby_info("") == []

    def test_entry_without_args(self):
        entries = parse_grubby_info('index=0\nkernel="/boot/vmlinuz-a"\n')
        assert entries[0].get("args", "") == ""


class TestMergePciParam:
    def test_add_to_empty(self):
        assert merge_pci_param([], "config_acs='x'") == "pci=config_acs='x'"

    def test_keeps_other_subopts(self):
        assert (
            merge_pci_param(["pci=realloc"], "config_acs='x'")
            == "pci=realloc,config_acs='x'"
        )

    def test_replaces_existing_config_acs(self):
        assert (
            merge_pci_param(["pci=config_acs='old'"], "config_acs='new'")
            == "pci=config_acs='new'"
        )

    def test_replaces_config_acs_and_keeps_the_rest(self):
        assert (
            merge_pci_param(["pci=realloc,config_acs='old'"], "config_acs='new'")
            == "pci=realloc,config_acs='new'"
        )

    def test_remove_keeps_other_subopts(self):
        assert merge_pci_param(["pci=realloc,config_acs='x'"], None) == "pci=realloc"

    def test_remove_last_subopt_gives_none(self):
        assert merge_pci_param(["pci=config_acs='x'"], None) is None

    def test_nothing_at_all_gives_none(self):
        assert merge_pci_param([], None) is None

    def test_bare_pci_token(self):
        assert merge_pci_param(["pci"], None) is None


# ---------------------------------------------------------------------------
# GrubbyBackend
# ---------------------------------------------------------------------------

KERNEL_A = "/boot/vmlinuz-a"
KERNEL_B = "/boot/vmlinuz-b"
SUBOPT = f"config_acs='{ACS_ARG}'"


@contextlib.contextmanager
def quiet():
    """Swallow the informational output of a non dry-run apply/remove."""
    with contextlib.redirect_stdout(io.StringIO()):
        yield


class FakeGrubby:
    """Stand-in for grubby, modelling that it matches arguments by name on
    both the --args and the --remove-args paths."""

    def __init__(self, entries, apply_changes: bool = True):
        self.entries = [{"kernel": k, "args": a} for k, a in entries]
        self.apply_changes = apply_changes
        self.calls: List[List[str]] = []

    def check_output(self, cmd, text=False):
        assert cmd == ["grubby", "--info", "ALL"], cmd
        out = []
        for i, entry in enumerate(self.entries):
            out.append(f"index={i}")
            out.append(f'kernel="{entry["kernel"]}"')
            out.append(f'args="{entry["args"]}"')
            out.append('initrd="/boot/initramfs.img"')
            out.append('title="Linux"')
        return "\n".join(out) + "\n"

    def check_call(self, cmd):
        self.calls.append(list(cmd))
        assert cmd[0] == "grubby" and cmd[1] == "--update-kernel"
        target, op, value = cmd[2], cmd[3], cmd[4]
        if not self.apply_changes:
            return
        name = value.split("=", 1)[0]
        for entry in self.entries:
            if target != "ALL" and target != entry["kernel"]:
                continue
            tokens = [
                token
                for token in split_cmdline(entry["args"])
                if token != name and not token.startswith(name + "=")
            ]
            if op == "--args":
                tokens.append(value)
            entry["args"] = " ".join(tokens)

    def install(self):
        return mock.patch.multiple(
            rdma_topo.subprocess,
            check_output=self.check_output,
            check_call=self.check_call,
        )


class TestGrubbyBackend:
    def test_apply_emits_expected_argv(self):
        fake = FakeGrubby([(KERNEL_A, "ro quiet"), (KERNEL_B, "ro quiet")])
        with fake.install(), quiet():
            GrubbyBackend().apply(ACS_ARG, dry_run=False)
        assert fake.calls == [
            ["grubby", "--update-kernel", "ALL", "--args", f"pci={SUBOPT}"]
        ]

    def test_apply_uses_space_separated_options(self):
        # grubby-bls only matches '--args VALUE', '--args=VALUE' is rejected
        fake = FakeGrubby([(KERNEL_A, "ro")])
        with fake.install(), quiet():
            GrubbyBackend().apply(ACS_ARG, dry_run=False)
        assert all("=" not in arg for arg in fake.calls[0][:4:2])
        assert fake.calls[0][3] == "--args"

    def test_apply_is_idempotent(self):
        fake = FakeGrubby([(KERNEL_A, "ro"), (KERNEL_B, "ro")])
        with fake.install(), quiet():
            GrubbyBackend().apply(ACS_ARG, dry_run=False)
            assert len(fake.calls) == 1
            GrubbyBackend().apply(ACS_ARG, dry_run=False)
            assert len(fake.calls) == 1

    def test_apply_preserves_other_pci_args(self):
        fake = FakeGrubby([(KERNEL_A, "ro pci=realloc")])
        with fake.install(), quiet():
            GrubbyBackend().apply(ACS_ARG, dry_run=False)
        assert fake.calls[0][4] == f"pci=realloc,{SUBOPT}"
        assert "pci=realloc" in fake.entries[0]["args"]

    def test_apply_replaces_a_stale_value(self):
        fake = FakeGrubby([(KERNEL_A, "ro pci=config_acs='xx000x0@0000:00:00.0'")])
        with fake.install(), quiet():
            GrubbyBackend().apply(ACS_ARG, dry_run=False)
        assert fake.entries[0]["args"] == f"ro pci={SUBOPT}"

    def test_apply_uses_all_when_only_some_entries_need_changing(self):
        # ALL is the only form that also updates /etc/kernel/cmdline, which is
        # what newly installed kernels inherit, so it must be preferred even
        # when one entry is already correct.
        fake = FakeGrubby([(KERNEL_A, f"ro pci={SUBOPT}"), (KERNEL_B, "ro")])
        with fake.install(), quiet():
            GrubbyBackend().apply(ACS_ARG, dry_run=False)
        assert fake.calls == [
            ["grubby", "--update-kernel", "ALL", "--args", f"pci={SUBOPT}"]
        ]

    def test_apply_per_entry_when_entries_want_different_values(self):
        fake = FakeGrubby([(KERNEL_A, "ro pci=realloc"), (KERNEL_B, "ro")])
        with fake.install(), quiet():
            GrubbyBackend().apply(ACS_ARG, dry_run=False)
        assert fake.calls == [
            ["grubby", "--update-kernel", KERNEL_A, "--args", f"pci=realloc,{SUBOPT}"],
            ["grubby", "--update-kernel", KERNEL_B, "--args", f"pci={SUBOPT}"],
        ]
        assert fake.entries[0]["args"] == f"ro pci=realloc,{SUBOPT}"
        assert fake.entries[1]["args"] == f"ro pci={SUBOPT}"

    def test_apply_verification_failure_raises(self):
        fake = FakeGrubby([(KERNEL_A, "ro")], apply_changes=False)
        with fake.install():
            with pytest.raises(rdma_topo.CommandError, match="did not set"):
                GrubbyBackend().apply(ACS_ARG, dry_run=False)

    def test_apply_dry_run_prints_and_calls_nothing(self):
        fake = FakeGrubby([(KERNEL_A, "ro")])
        buf = io.StringIO()
        with fake.install():
            with contextlib.redirect_stdout(buf):
                GrubbyBackend().apply(ACS_ARG, dry_run=True)
        assert fake.calls == []
        # The printed command must be copy paste safe, parsing it back as a
        # shell command has to give exactly the argv that would have run.
        assert shlex.split(buf.getvalue().strip()) == [
            "grubby",
            "--update-kernel",
            "ALL",
            "--args",
            f"pci={SUBOPT}",
        ]

    def test_dry_run_with_nothing_to_do_prints_a_comment(self):
        fake = FakeGrubby([(KERNEL_A, f"ro pci={SUBOPT}")])
        buf = io.StringIO()
        with fake.install():
            with contextlib.redirect_stdout(buf):
                GrubbyBackend().apply(ACS_ARG, dry_run=True)
        assert buf.getvalue().startswith("#")
        assert fake.calls == []

    def test_remove_drops_only_our_subopt(self):
        fake = FakeGrubby([(KERNEL_A, f"ro pci=realloc,{SUBOPT}")])
        with fake.install(), quiet():
            assert GrubbyBackend().remove(dry_run=False) is True
        assert fake.calls[0][3:] == ["--args", "pci=realloc"]
        assert fake.entries[0]["args"] == "ro pci=realloc"

    def test_remove_uses_remove_args_when_nothing_else_is_left(self):
        fake = FakeGrubby([(KERNEL_A, f"ro pci={SUBOPT}")])
        with fake.install(), quiet():
            assert GrubbyBackend().remove(dry_run=False) is True
        assert fake.calls[0][3:] == ["--remove-args", "pci"]
        assert fake.entries[0]["args"] == "ro"

    def test_remove_with_nothing_set_returns_false(self):
        fake = FakeGrubby([(KERNEL_A, "ro quiet")])
        with fake.install(), quiet():
            assert GrubbyBackend().remove(dry_run=False) is False
        assert fake.calls == []

    def test_whitespace_in_existing_value_is_refused(self):
        fake = FakeGrubby([(KERNEL_A, "ro pci=config_acs='a; b'")])
        with fake.install():
            with pytest.raises(rdma_topo.CommandError, match="whitespace"):
                GrubbyBackend().apply(ACS_ARG, dry_run=False)

    def test_missing_grubby_raises_command_error(self):
        def missing(cmd, text=False):
            raise FileNotFoundError(2, "No such file or directory", "grubby")

        with mock.patch.object(rdma_topo.subprocess, "check_output", missing):
            with pytest.raises(rdma_topo.CommandError, match="Could not run grubby"):
                GrubbyBackend().apply(ACS_ARG, dry_run=True)

    def test_grubby_failure_raises_command_error(self):
        def failing(cmd, text=False):
            raise rdma_topo.subprocess.CalledProcessError(1, cmd)

        with mock.patch.object(rdma_topo.subprocess, "check_output", failing):
            with pytest.raises(rdma_topo.CommandError, match="exit code 1"):
                GrubbyBackend().apply(ACS_ARG, dry_run=True)

    def test_no_boot_entries_raises_command_error(self):
        fake = FakeGrubby([])
        with fake.install():
            with pytest.raises(rdma_topo.CommandError, match="did not return any boot entry"):
                GrubbyBackend().apply(ACS_ARG, dry_run=True)


# ---------------------------------------------------------------------------
# select_cmdline_backend
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def fake_system(has_grub_dropin_dir: bool, commands: List[str]):
    with mock.patch.object(
        rdma_topo.os.path, "isdir", lambda p: has_grub_dropin_dir
    ), mock.patch.object(
        rdma_topo.shutil, "which", lambda c: f"/usr/sbin/{c}" if c in commands else None
    ):
        yield


class TestSelectCmdlineBackend:
    def test_debian_selects_update_grub(self):
        with fake_system(True, ["update-grub"]):
            backend = select_cmdline_backend("auto", None)
        assert isinstance(backend, UpdateGrubBackend)
        assert backend.output == rdma_topo.DEFAULT_GRUB_DROPIN

    def test_rhel_selects_grubby(self):
        with fake_system(False, ["grubby"]):
            assert isinstance(select_cmdline_backend("auto", None), GrubbyBackend)

    def test_update_grub_wins_when_both_are_present(self):
        with fake_system(True, ["update-grub", "grubby"]):
            assert isinstance(select_cmdline_backend("auto", None), UpdateGrubBackend)

    def test_neither_raises(self):
        with fake_system(False, []):
            with pytest.raises(rdma_topo.CommandError, match="Could not determine"):
                select_cmdline_backend("auto", None)

    def test_explicit_output_forces_update_grub(self):
        with fake_system(False, ["grubby"]):
            backend = select_cmdline_backend("auto", "/tmp/acs.cfg")
        assert isinstance(backend, UpdateGrubBackend)
        assert backend.output == "/tmp/acs.cfg"

    def test_explicit_backend_overrides_detection(self):
        with fake_system(True, ["update-grub"]):
            assert isinstance(select_cmdline_backend("grubby", None), GrubbyBackend)

    def test_output_with_grubby_raises(self):
        with fake_system(False, ["grubby"]):
            with pytest.raises(rdma_topo.CommandError, match="--output"):
                select_cmdline_backend("grubby", "/tmp/acs.cfg")

    def test_forced_update_grub_uses_the_default_path(self):
        with fake_system(False, ["grubby"]):
            backend = select_cmdline_backend("update-grub", None)
        assert backend.output == rdma_topo.DEFAULT_GRUB_DROPIN
