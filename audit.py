"""Revisão offline e limitada de cabeçalhos HTTP capturados em JSON."""

import argparse
import json
import re
import sys
from pathlib import Path


def audit(document):
    if not isinstance(document, dict):
        raise ValueError("A entrada deve ser um objeto JSON")
    scheme = document.get("scheme")
    raw = document.get("headers")
    if scheme not in ("https", "http") or not isinstance(raw, dict):
        raise ValueError("Informe scheme http/https e headers como objeto")
    headers = {}
    for name, value in raw.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("Cabeçalhos devem ter nomes e valores de texto")
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ValueError("Nome de cabeçalho inválido")
        key = name.lower()
        if key in headers or "\r" in value or "\n" in value:
            raise ValueError("Cabeçalho duplicado ou valor com quebra de linha")
        headers[key] = value.strip()

    checks = []

    def add(rule, status, explanation):
        checks.append(dict(rule=rule, status=status, explanation=explanation))

    hsts = headers.get("strict-transport-security", "")
    if scheme == "http":
        add("hsts", "not_applicable", "HSTS enviado por HTTP não é aplicado pelo navegador.")
    elif not hsts:
        add("hsts", "missing", "HSTS ausente nesta captura HTTPS; revisar configuração.")
    else:
        ages = []
        for directive in hsts.split(";"):
            match = re.fullmatch(
                r'max-age\s*=\s*(?:"([0-9]+)"|([0-9]+))', directive.strip(), re.IGNORECASE
            )
            if match:
                ages.append(int(match.group(1) or match.group(2)))
        if len(ages) == 1 and ages[0] > 0:
            add(
                "hsts",
                "basic_check_passed",
                "Um max-age positivo encontrado; política completa requer revisão.",
            )
        else:
            add("hsts", "review", "max-age ausente, duplicado, inválido ou zero.")

    nosniff = headers.get("x-content-type-options", "")
    if nosniff.lower() == "nosniff":
        add("nosniff", "basic_check_passed", "Valor nosniff encontrado.")
    elif nosniff:
        add("nosniff", "review", "Valor diferente de nosniff; revisar configuração.")
    else:
        add("nosniff", "missing", "X-Content-Type-Options ausente nesta captura.")

    csp = headers.get("content-security-policy", "")
    if csp:
        add("csp", "manual_review", "CSP presente; diretivas e eficácia não foram avaliadas.")
    elif headers.get("content-security-policy-report-only"):
        add("csp", "review", "Somente Report-Only encontrado; não substitui política aplicada.")
    else:
        add("csp", "missing", "Content-Security-Policy ausente nesta captura.")

    return {
        "scheme": scheme,
        "checks": checks,
        "scope": "Captura fornecida; sem rede, sem nota de segurança e sem validação no navegador.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Arquivo JSON com scheme e headers")
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.input.read_text(encoding="utf-8"))
        result = audit(document)
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        print(f"Erro: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
