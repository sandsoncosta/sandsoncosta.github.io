from pathlib import Path
import json
import re

ROOT = Path(__file__).resolve().parent
BLOG = ROOT / 'content' / 'blog'
OUTPUT = ROOT / 'static' / 'admin' / 'config.yml'

FIELDS = [
    ('Título', 'title', 'string'),
    ('URL personalizada', 'url', 'string'),
    ('Data', 'date', 'datetime'),
    ('Rascunho', 'draft', 'boolean'),
    ('Descrição', 'description', 'text'),
    ('Não indexar', 'noindex', 'boolean'),
    ('Destaque', 'featured', 'boolean'),
    ('Fixado', 'pinned', 'boolean'),
    ('Comentários', 'comments', 'boolean'),
    ('Séries', 'series', 'list'),
    ('Categorias', 'categories', 'list'),
    ('Tags', 'tags', 'list'),
    ('Autores', 'authors', 'list'),
    ('Conteúdo', 'body', 'markdown'),
]


def q(value):
    return json.dumps(str(value), ensure_ascii=False)


def main():
    if not BLOG.is_dir():
        raise SystemExit(f'Pasta não encontrada: {BLOG}')
    if not OUTPUT.exists():
        raise SystemExit(f'Configuração não encontrada: {OUTPUT}')
    content = OUTPUT.read_text(encoding='utf-8')
    marker = '\ncollections:'
    match = re.search(r'(?m)^collections:\s*$', content)
    if not match:
        raise SystemExit('Não encontrei a seção collections: no config.yml')
    # Preserve backend, media folders and other global settings.
    prefix = content[:match.start()].rstrip() + '\n\n'
    files = sorted(BLOG.glob('*/index.md'), key=lambda p: p.parent.name.casefold())
    if not files:
        raise SystemExit('Nenhum arquivo content/blog/*/index.md encontrado')
    lines = ['collections:', '  - name: "artigos"', '    label: "Artigos existentes"', '    files:']
    for i, path in enumerate(files, 1):
        rel = path.relative_to(ROOT).as_posix()
        name = path.parent.name
        lines.extend([
            f'      - name: {q("artigo-" + str(i).zfill(4))}',
            f'        label: {q(name)}',
            f'        file: {q(rel)}',
            '        fields:'
        ])
        for label, field, widget in FIELDS:
            extras = ', required: false' if field not in ('title', 'body') else ''
            lines.append(f'          - {{ label: {q(label)}, name: {q(field)}, widget: {q(widget)}{extras} }}')
    OUTPUT.write_text(prefix + '\n'.join(lines) + '\n', encoding='utf-8')
    print(f'Catálogo gerado: {len(files)} artigos em {OUTPUT}')


if __name__ == '__main__':
    main()