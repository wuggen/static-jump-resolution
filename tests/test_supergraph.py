import nose
import nose.tools as nt
import angr
from static_jump_resolution.supergraph.supergraph import DummyNode, supergraph_from_cfg

import os.path
BIN_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'bin')

def addrs_to_nodes(graph):
    """ Generate a mapping from node addresses to nodes from a graph.

    :param nx.DiGraph graph:
    :return: dict
    """
    m = {}
    for n in graph.nodes:
        if type(n) is DummyNode:
            continue

        m[n.addr] = n

    return m

def check_edges(bin_name, edges):
    """ Generate a fast CFG on the given binary, convert to supergraph, and ensure the conversion
    is correct according to the expected edges.

    Each edge should be a tuple of (source, dest, jumpkind), where jumpkind is one of 'Ijk_Boring',
    'Ijk_Call', or 'Ijk_Ret'. When the source (resp. dest) node is a normal CFGNode, source (resp.
    dest) should be given as its start address. When it is a dummy node, it should be given as a
    pair of (parent_address, dummy_type), where parent_address is the start address of the parent
    node and dummy_type is one of 'Dummy_Call' or 'Dummy_Ret'.

    :param str bin_name: The path to the binary file under the tests/bin directory.
    :param list edges: A list of (source, dest, jumpkind) edges.
    :return: None
    """
    path = os.path.join(BIN_PATH, bin_name)
    proj = angr.Project(path, auto_load_libs=False)
    base_addr = proj.loader.main_object.mapped_base

    cfg = proj.analyses.CFGFast()
    supergraph = supergraph_from_cfg(cfg)
    nodes = addrs_to_nodes(supergraph)

    def node_from_def(nodedef):
        if type(nodedef) is int:
            return nodes[nodedef + base_addr]
        elif type(nodedef) is tuple:
            par_addr, dummy_type = nodedef
            parent = nodes[par_addr + base_addr]
            return DummyNode(parent, dummy_type)
        else:
            return None

    def def_from_node(node):
        if type(node) is DummyNode:
            return (node.parent_node.addr - base_addr, node.dummy_type)
        else:
            return node.addr - base_addr

    def nodestr(nodedef):
        if type(nodedef) is int:
            return "0x%x" % nodedef
        elif type(nodedef) is tuple:
            return "(0x%x, %s)" % nodedef
        else:
            return None

    for (src, dst, jumpkind) in edges:
        srcnode = node_from_def(src)
        dstnode = node_from_def(dst)

        srcstr = nodestr(src)
        dststr = nodestr(dst)

        nt.ok_(srcnode in supergraph, 'src (%s) not in supergraph' % srcstr)
        nt.ok_(dstnode in supergraph, 'dst (%s) not in supergraph' % dststr)
        nt.ok_((srcnode, dstnode) in supergraph.edges, 'edge (%s, %s) not in supergraph' % (srcstr, \
            dststr))

        actual_jk = supergraph.edges[(srcnode, dstnode)]['jumpkind']
        nt.eq_(actual_jk, jumpkind, 'jumpkind %s != %s for edge (%s, %s)' % (actual_jk, jumpkind, src, dst))

    for ((srcnode, dstnode), attrs) in supergraph.edges.items():
        src = def_from_node(srcnode)
        dst = def_from_node(dstnode)
        jumpkind = attrs['jumpkind']

        srcstr = nodestr(src)
        dststr = nodestr(dst)

        nt.ok_((src, dst, jumpkind) in edges, 'edge (%s, %s, %s) in supergraph but not in spec' % \
                (srcstr, dststr, jumpkind))

def test_simple():
    filename = "simple_supergraph.o"
    edges = [
        (0x0, (0x0, 'Dummy_Call'), 'Ijk_Boring'),
        ((0x0, 'Dummy_Call'), 0x10, 'Ijk_Call'),
        (0x10, (0x0, 'Dummy_Ret'), 'Ijk_Ret'),
        ((0x0, 'Dummy_Ret'), 0x9, 'Ijk_Boring')
        ]
    check_edges(filename, edges)

def test_multiple_returns():
    filename = "multiple_returns.o"
    edges = [
        (0x0, (0x0, 'Dummy_Call'), 'Ijk_Boring'),
        ((0x0, 'Dummy_Call'), 0x27, 'Ijk_Call'),
        (0x27, (0x0, 'Dummy_Ret'), 'Ijk_Ret'),
        ((0x0, 'Dummy_Ret'), 0xe, 'Ijk_Boring'),
        (0xe, 0x1b, 'Ijk_Boring'),
        (0x1b, 0x20, 'Ijk_Boring'),
        (0x1b, 0x12, 'Ijk_Boring'),
        (0x12, (0x12, 'Dummy_Call'), 'Ijk_Boring'),
        ((0x12, 'Dummy_Call'), 0x27, 'Ijk_Call'),
        (0x27, (0x12, 'Dummy_Ret'), 'Ijk_Ret'),
        ((0x12, 'Dummy_Ret'), 0x19, 'Ijk_Boring'),
        (0x19, 0x1b, 'Ijk_Boring')
        ]
    check_edges(filename, edges)

if __name__ == '__main__':
    nose.main()
