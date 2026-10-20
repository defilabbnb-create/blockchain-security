"""Resolve Solidity struct references by AST declaration ID in Slither 0.11.4.

Slither's name lookup can lose one of two same-named libraries imported through
aliases. Solidity's referencedDeclaration is unambiguous. Preserve the source
and AST and bind only exact declaration locations; all other types use Slither.
"""
import sys


def install_struct_resolution(compilation):
    from slither.solc_parsing.solidity_types import type_parsing
    from slither.core.solidity_types.user_defined_type import UserDefinedType
    original = type_parsing.parse_type
    declarations = {}
    units = list(compilation.compilation_units.values())
    if len(units) != 1:
        raise RuntimeError('Struct compatibility adapter requires one compilation unit')

    def walk(node, filename):
        if isinstance(node, dict):
            if node.get('nodeType') == 'StructDefinition':
                start, length, _ = map(int, node['src'].split(':'))
                declarations[node['id']] = (filename.absolute, start, length)
            for value in node.values():
                walk(value, filename)
        elif isinstance(node, list):
            for value in node:
                walk(value, filename)

    for filename, source_unit in units[0].source_units.items():
        walk(source_unit.ast, filename)
    stats = {'adapter': 'AST declaration ID struct resolution for Slither 0.11.4', 'resolvedReferences': 0}

    def parse_type(node, context):
        if isinstance(node, dict) and node.get('nodeType') == 'UserDefinedTypeName':
            reference = node.get('referencedDeclaration', node.get('pathNode', {}).get('referencedDeclaration'))
            location = declarations.get(reference)
            if location:
                sl = context.compilation_unit
                structures = list(sl.structures_top_level)
                for contract in sl.contracts:
                    structures.extend(contract.structures)
                matches = []
                for structure in structures:
                    source = structure.source_mapping
                    if (source.filename.absolute, source.start, source.length) == location and all(structure is not old for old in matches):
                        matches.append(structure)
                if len(matches) != 1:
                    raise RuntimeError('Unable to uniquely resolve struct declaration ID {}'.format(reference))
                resolved = UserDefinedType(matches[0])
                type_parsing._add_type_references(resolved, node['src'], sl)
                stats['resolvedReferences'] += 1
                return resolved
        return original(node, context)

    # Slither imports parse_type into multiple parser modules before this hook.
    for name, module in list(sys.modules.items()):
        if name.startswith('slither.') and getattr(module, 'parse_type', None) is original:
            module.parse_type = parse_type
    return stats
