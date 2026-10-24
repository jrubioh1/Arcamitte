import shutil
import tempfile
from pathlib import Path
import pytest
from django.conf import settings


@pytest.fixture(autouse=True, scope="session")
def auto_cleanup_test_media():
    """
    Garantiza que ninguna ejecución de pruebas persista archivos generados
    en el directorio de medios (MEDIA_ROOT) o en el árbol del proyecto.
    """
    temp_dir = tempfile.mkdtemp(prefix="arca_pytest_media_")
    orig_media = settings.MEDIA_ROOT
    settings.MEDIA_ROOT = Path(temp_dir)

    yield

    settings.MEDIA_ROOT = orig_media
    shutil.rmtree(temp_dir, ignore_errors=True)

    # Limpieza defensiva adicional de cualquier residuo en media/
    real_media_path = Path(orig_media)
    if real_media_path.exists():
        for file_path in real_media_path.glob("**/*"):
            if file_path.is_file():
                try:
                    file_path.unlink()
                except OSError:
                    pass
