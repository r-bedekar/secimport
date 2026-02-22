"""Tests for output sinks."""

import csv
import json

from secimport.outputs import CSVOutput, JSONOutput, OutputRegistry, StdoutOutput


class TestOutputRegistry:
    def test_outputs_registered(self):
        registry = OutputRegistry.list_outputs()
        assert "json" in registry
        assert "csv" in registry
        assert "stdout" in registry
        assert "webhook" in registry

    def test_get_by_type(self):
        assert OutputRegistry.get("json") is JSONOutput
        assert OutputRegistry.get("nonexistent") is None


class TestJSONOutput:
    def test_write(self, tmp_path):
        out_file = tmp_path / "out.json"
        output = JSONOutput(path=str(out_file))
        count = output.write(iter([{"hostname": "web01"}, {"hostname": "web02"}]))
        assert count == 2

        data = json.loads(out_file.read_text())
        assert len(data) == 2
        assert data[0]["hostname"] == "web01"

    def test_write_empty(self, tmp_path):
        out_file = tmp_path / "empty.json"
        output = JSONOutput(path=str(out_file))
        count = output.write(iter([]))
        assert count == 0


class TestCSVOutput:
    def test_write(self, tmp_path):
        out_file = tmp_path / "out.csv"
        output = CSVOutput(path=str(out_file))
        count = output.write(
            iter([
                {"hostname": "web01", "ip": "10.0.0.1"},
                {"hostname": "web02", "ip": "10.0.0.2"},
            ])
        )
        assert count == 2

        with out_file.open() as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["hostname"] == "web01"

    def test_write_empty(self, tmp_path):
        out_file = tmp_path / "empty.csv"
        output = CSVOutput(path=str(out_file))
        count = output.write(iter([]))
        assert count == 0


class TestStdoutOutput:
    def test_write(self, capsys):
        output = StdoutOutput()
        count = output.write(iter([{"hostname": "web01"}]))
        assert count == 1

        captured = capsys.readouterr()
        assert "web01" in captured.out
