---
title: python图论库Networkx
date: 2019-04-08 20:01:55
tags: Python
---

### Networkx简介

Networkx可以很直观地创建，操作很复杂的网络拓扑结构

#### 创建图

```python
import networkx

G = networkx.Graph() #创建一个无向图
```

<!--more-->

#### 点

```python
G.add_node() #单个点的插入
G.add_node_from() #多个点以list的形式插入
#example: 
L = [1,2,3,4,5,6]
G.add_node_from(L)
#alert
#对于字符串之类的可迭代对象
S = "test"
G.add_node(S) #添加了一个节点 test
G.add_node_from(S) #添加了4个节点 t,e,s,t
G.remove_node() #移除指定点
G.remove_node_from() #在图中移除可迭代对象中的节点
G.nodes() #打印G中的所有节点
G.number_of_nodes() #返回点的数量
```

点的类型可以是任何哈希对象：字符串、数字、图像、XML对象、另一个Graph，只要调用对象的 `.__hash__`属性，只要返回的不是None就是可hash的对象

#### 边

```python
G.add_edge(node1,node2) #node为上面介绍的点
L = [(1,2),(3,4)]
G.add_edge.from(L) #批量添加边
G.remove_edge(node1,node2) #删除边
G.remove_edge_from(L) #批量删除边
G.number_of_edges() #返回
```

#### 无向图method

| method                                                       | explanation                                    |
| ------------------------------------------------------------ | ---------------------------------------------- |
| [`Graph.has_node`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.has_node.html#networkx.Graph.has_node)(n) | Return True if the graph contains the node n.  |
| [`Graph.__contains__`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.__contains__.html#networkx.Graph.__contains__)(n) | Return True if n is a node, False otherwise.   |
| [`Graph.has_edge`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.has_edge.html#networkx.Graph.has_edge)(u, v) | Return True if the edge (u,v) is in the graph. |
| [`Graph.order`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.order.html#networkx.Graph.order)() | Return the number of nodes in the graph.       |
| [`Graph.number_of_nodes`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.number_of_nodes.html#networkx.Graph.number_of_nodes)() | Return the number of nodes in the graph.       |
| [`Graph.__len__`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.__len__.html#networkx.Graph.__len__)() | Return the number of nodes.                    |
| [`Graph.degree`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.degree.html#networkx.Graph.degree)([nbunch, weight]) | Return the degree of a node or nodes.          |
| [`Graph.degree_iter`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.degree_iter.html#networkx.Graph.degree_iter)([nbunch, weight]) | Return an iterator for (node, degree).         |
| [`Graph.size`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.size.html#networkx.Graph.size)([weight]) | Return the number of edges.                    |
| [`Graph.number_of_edges`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.number_of_edges.html#networkx.Graph.number_of_edges)([u, v]) | Return the number of edges between two nodes.  |
| [`Graph.nodes_with_selfloops`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.nodes_with_selfloops.html#networkx.Graph.nodes_with_selfloops)() | Return a list of nodes with self loops.        |
| [`Graph.selfloop_edges`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.selfloop_edges.html#networkx.Graph.selfloop_edges)([data, default]) | Return a list of selfloop edges.               |
| [`Graph.number_of_selfloops`](https://link.jianshu.com?t=https://networkx.github.io/documentation/networkx-1.10/reference/generated/networkx.Graph.number_of_selfloops.html#networkx.Graph.number_of_selfloops)() | Return the number of selfloop edges.           |



#### 生成图

```python

```



#### 