# HTTP Header Review

CLI Python para revisar uma captura local de cabeçalhos HTTP em JSON. Aplica três verificações explícitas: HSTS, `X-Content-Type-Options` e presença de CSP. Não acessa sites, não faz varreduras e não atribui uma nota geral de segurança.

Projeto educacional preparado com assistência do Codex para estudar configuração defensiva e limites de verificações automáticas.

## Executar

Requer Python 3.10 ou superior, sem dependências externas:

```sh
python audit.py examples/review.json
python -m unittest -v
```

No Linux, use `python3` se necessário. A saída é JSON. Código de saída 0 significa análise concluída, mesmo com itens a revisar. Código 2 indica erro de leitura ou entrada inválida.

## Entrada

```json
{
  "scheme": "https",
  "headers": {
    "Strict-Transport-Security": "max-age=3600",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'self'"
  }
}
```

Use `scheme` igual a `http` ou `https`, conforme a resposta capturada. Nomes de cabeçalhos não diferenciam maiúsculas e minúsculas. Nomes repetidos com capitalização diferente e valores com quebras de linha são rejeitados. O formato não representa múltiplas instâncias do mesmo cabeçalho.

## Regras e limites

| Regra | Verificação realizada |
| --- | --- |
| HSTS | Em HTTPS, procura exatamente uma diretiva reconhecida `max-age` positiva. Zero, ausência ou configuração não reconhecida requer revisão. Em HTTP, não marca a verificação como aprovada. |
| nosniff | Confere o valor `nosniff` de `X-Content-Type-Options`. |
| CSP | Registra presença para revisão manual. Uma política somente Report-Only é identificada separadamente. |

`basic_check_passed` significa apenas que a condição descrita foi encontrada. O programa não implementa o parser completo de HSTS ou CSP e não avalia a eficácia das políticas. Não verifica TLS, domínio, redirects, preload, HTML, cookies ou comportamento real de navegadores. A captura pode estar desatualizada ou representar somente uma resposta.

O exemplo incluído sinaliza HSTS com `max-age=0`, reconhece `nosniff` e identifica CSP apenas Report-Only. Cabeçalhos fora dessas verificações não são reproduzidos no relatório.

## Testes

Nove testes cobrem cabeçalhos ausentes, capitalização, HSTS em HTTP, idade zero, diretivas repetidas, Report-Only, entradas ambíguas, descarte de valores não analisados e execução da CLI.

## Referências

- [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security)
- [MDN: X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options)
- [MDN: Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy)

## Próximos passos

Adicionar fixtures com múltiplas respostas e uma representação que preserve cabeçalhos repetidos, além de ampliar os testes. Esses recursos ainda não estão implementados.
