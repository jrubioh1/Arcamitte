from pathlib import Path
from django.test import SimpleTestCase
from django.utils import translation
from django.utils.translation import gettext as _
from scripts.build_en_translations import extract_code_msgids, unescape_po_string


class InternationalizationAndMigrationsCompletenessTests(SimpleTestCase):
    """
    Verifica la completitud al 100% de la internacionalización (i18n) en código Python,
    plantillas HTML y catálogos gettext (.po y .mo), así como la consolidación de
    migraciones en una única migración inicial limpia (0001_initial.py).
    """

    def test_single_clean_initial_migration(self):
        repo_root = Path(__file__).resolve().parent.parent.parent
        migrations_dir = repo_root / "arcamitte" / "migrations"
        migration_files = sorted(
            f.name
            for f in migrations_dir.glob("*.py")
            if f.name != "__init__.py"
        )
        self.assertEqual(
            migration_files,
            ["0001_initial.py"],
            f"Se esperaba únicamente ['0001_initial.py'], pero se encontraron: {migration_files}",
        )

    def test_po_catalogs_have_zero_missing_empty_or_fuzzy_entries(self):
        repo_root = Path(__file__).resolve().parent.parent.parent
        arcamitte_dir = repo_root / "arcamitte"
        code_msgids = extract_code_msgids(arcamitte_dir)
        self.assertGreater(len(code_msgids), 1000)

        for lang in ("en", "es"):
            po_path = arcamitte_dir / "locale" / lang / "LC_MESSAGES" / "django.po"
            mo_path = arcamitte_dir / "locale" / lang / "LC_MESSAGES" / "django.mo"
            self.assertTrue(po_path.exists(), f"No existe {po_path}")
            self.assertTrue(mo_path.exists(), f"No existe {mo_path}")

            content = po_path.read_text(encoding="utf-8")
            self.assertNotIn("#, fuzzy", content, f"Existen entradas fuzzy en {po_path}")

            blocks = content.split("\n\n")
            po_entries = {}
            empty_entries = []
            for b in blocks:
                if "msgid " not in b:
                    continue
                lines = b.splitlines()
                mode = None
                msgid_parts = []
                msgstr_parts = []
                for l in lines:
                    l_strip = l.strip()
                    if l_strip.startswith("#"):
                        continue
                    if l_strip.startswith("msgid "):
                        mode = "id"
                        msgid_parts.append(l_strip[6:].strip('"'))
                    elif l_strip.startswith("msgstr "):
                        mode = "str"
                        msgstr_parts.append(l_strip[7:].strip('"'))
                    elif l_strip.startswith('"') and l_strip.endswith('"'):
                        if mode == "id":
                            msgid_parts.append(l_strip[1:-1])
                        elif mode == "str":
                            msgstr_parts.append(l_strip[1:-1])
                raw_id = unescape_po_string("".join(msgid_parts))
                raw_str = unescape_po_string("".join(msgstr_parts))
                if raw_id:
                    po_entries[raw_id] = raw_str
                    po_entries[raw_id.replace("%%", "%")] = raw_str
                    if not raw_str.strip():
                        empty_entries.append(raw_id)

            self.assertEqual(
                empty_entries,
                [],
                f"Catálogo [{lang}] tiene {len(empty_entries)} entradas vacías: {empty_entries[:5]}",
            )

            missing = [
                m
                for m in code_msgids
                if m not in po_entries and m.replace("%", "%%") not in po_entries
            ]
            self.assertEqual(
                missing,
                [],
                f"Catálogo [{lang}] no contiene {len(missing)} msgids del código: {missing[:5]}",
            )

    def test_runtime_mo_translations_en_and_es(self):
        with translation.override("en"):
            self.assertEqual(_("Analítica y Métricas"), "Analytics & Metrics")
            self.assertEqual(_("Gobernanza 2FA"), "2FA Governance")
            self.assertEqual(
                _("El baneo sobre la dirección IP %(ip)s ha sido revocado.")
                % {"ip": "10.0.0.1"},
                "The ban on IP address 10.0.0.1 has been revoked.",
            )
            self.assertEqual(
                _("Segundo factor (2FA) %(action)s para el usuario '%(username)s'.")
                % {"action": _("exigido"), "username": "alice"},
                "Two-factor authentication (2FA) enforced for user 'alice'.",
            )

        with translation.override("es"):
            self.assertEqual(_("Analítica y Métricas"), "Analítica y Métricas")
            self.assertEqual(_("Gobernanza 2FA"), "Gobernanza 2FA")
