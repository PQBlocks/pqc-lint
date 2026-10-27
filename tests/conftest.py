import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def hybrid_path(tmp_path):
    """Hybrid sample (X25519 + HKDF + AES) that really calls an ML-KEM API."""
    src = (Path(__file__).parent / "test-instances" / "instance_04_pqc_mlkem_hybrid.py").read_text()
    p = tmp_path / "hybrid_channel.py"
    p.write_text("import oqs\nkem = oqs.KeyEncapsulation('ML-KEM-768')\n" + src)
    return p
