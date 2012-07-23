#!/usr/bin/python

class urlNode:
        def __init__(self, value, isLeaf=False):
                self.leaf = isLeaf
                self.content = value
                self.count = 1
                self.children = {}


class urlTree:
        def __init__(self):
                self.root = urlNode('root')

        # add the path to the tree and count:
        def add_path(self, path):
                cur_node = self.root
                sect = path.strip().split('/')
                for index in range(len(sect)):
                        item = sect[index]
                        if item.strip() == '':
                                continue
                        if cur_node.children.has_key(item):
                                cur_node.children[item].count += 1
                        else:
                                cur_node.children[item] = urlNode(item)
                        cur_node = cur_node.children[item]


        def output(self, file):
                f = open(file, 'w')
                #print 'level: 0 ', self.root.content
                f.write('level: 0 ' + self.root.content +'\n')
                cur_level = 1
                queue = {}
                queue[cur_level] = self.root.children
                while True:
                        nodes = queue[cur_level]
                        if len(nodes) == 0:
                                break
                        queue[cur_level+1] = {}
                        for key in nodes.keys():
                                if nodes[key].count > 1:
                                        f.write('level: ' + str(cur_level) + ' content: ' + key + ' count: ' + str(nodes[key].count) + '\n')
                                        print 'level:', cur_level, ' content:', key, ' count:', nodes[key].count
                                queue[cur_level+1].update(nodes[key].children)
                        cur_level += 1
                f.close()

	def print_tree(self, file):
		f = open(file, 'w')


