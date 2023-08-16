# -*- coding: utf-8 -*-
import csv
import json
import time

from py2neo import Graph, Node, Relationship
from py2neo import NodeMatcher, RelationshipMatcher

# 连接Neo4j
url = "bolt://localhost:7687"
username = "neo4j"
password = "Neo4j"

graph = Graph(url, auth=(username, password))  # 生成图谱
s_time = time.time()  # 记录时间
node_matcer = NodeMatcher(graph)
print("neo4j info: {}".format(str(graph)))
graph.delete_all()  # 清空旧图谱
# 生成组织节点
with open('./ctiic/vertex_organization.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
create_node_cnt = 0  # 记录生成的节点数
for i in range(1, len(data)):
    node = Node('organization', name=data[i][0], occurtime=data[i][1], motivation=data[i][2], introduction=data[i][3],
                referlink=data[i][4])
    graph.create(node)
    create_node_cnt += 1
    print(f"create {create_node_cnt} nodes.")
# 生成ip节点
with open('./ctiic/vertex_ip.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    node = Node('ip', name=data[i][0], value=data[i][1])
    graph.create(node)
    create_node_cnt += 1
    print(f"create {create_node_cnt} nodes.")
# 生成哈希节点
with open('./ctiic/vertex_sha256.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    node = Node('sha256', name=data[i][0], value=data[i][1], type=data[i][2])
    graph.create(node)
    create_node_cnt += 1
    print(f"create {create_node_cnt} nodes.")
# 生成产业节点
with open('./ctiic/vertex_industry.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    node = Node('industry', name=data[i][0])
    graph.create(node)
    create_node_cnt += 1
    print(f"create {create_node_cnt} nodes.")
# 生成域节点
with open('./ctiic/vertex_domain.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    node = Node('domain', name=data[i][0], value=data[i][1])
    graph.create(node)
    create_node_cnt += 1
    print(f"create {create_node_cnt} nodes.")
# 生成攻击手段节点
with open('./ctiic/vertex_attacktype.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    node = Node('attacktype', name=data[i][0], introduction=data[i][1])
    graph.create(node)
    create_node_cnt += 1
    print(f"create {create_node_cnt} nodes.")
# 生成国家节点
with open('./ctiic/vertex_area.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    node = Node('area', name=data[i][0])
    graph.create(node)
    create_node_cnt += 1
    print(f"create {create_node_cnt} nodes.")

# 部分不包括在csv的点单独创建
yin_yazhi = Node('area', name="叙利亚")
graph.create(yin_yazhi)
libaneng = Node('area', name="黎巴嫩")
graph.create(libaneng)
gong = Node('industry', name="工程行业")
graph.create(gong)
shiping = Node('industry', name="食品与安全")
graph.create(shiping)

# 建立联系
create_rel_cnt = 0  # 统计联系数量
# 生成组织和哈希的关联
with open('./ctiic/edge_organization_has_sha256.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    start_node = node_matcer.match('organization', name=data[i][0]).first()
    end_node = node_matcer.match('sha256', name=data[i][1]).first()
    graph.create(Relationship(start_node, "organization_has_sha256", end_node))
    graph.create(Relationship(end_node, "organization_has_sha256", start_node))  # 构建双线关联，方便从组织查询到哈希，从哈希查询到组织
    create_rel_cnt += 1
    print(f"create {create_rel_cnt} relations.")
# 生成组织和ip的关联
with open('./ctiic/edge_organization_has_ip.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    start_node = node_matcer.match('organization', name=data[i][0]).first()
    end_node = node_matcer.match('ip', name=data[i][1]).first()
    graph.create(Relationship(start_node, "organization_has_ip", end_node))
    graph.create(Relationship(end_node, "organization_has_ip", start_node))
    create_rel_cnt += 1
    print(f"create {create_rel_cnt} relations.")
# 生成组织和产业的关联
with open('./ctiic/edge_organization_has_industry.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    start_node = node_matcer.match('organization', name=data[i][0]).first()
    end_node = node_matcer.match('industry', name=data[i][1]).first()
    # if start_node is None:
    #     print(data[i][0])
    #     continue
    # if end_node is None:
    #     print(data[i][1])
    #     continue
    graph.create(Relationship(start_node, "organization_has_industry", end_node))
    graph.create(Relationship(end_node, "organization_has_industry", start_node))
    create_rel_cnt += 1
    print(f"create {create_rel_cnt} relations.")
# 生成组织和域名的关联
with open('./ctiic/edge_organization_has_domain.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    start_node = node_matcer.match('organization', name=data[i][0]).first()
    end_node = node_matcer.match('domain', name=data[i][1]).first()
    graph.create(Relationship(start_node, "organization_has_domain", end_node))
    graph.create(Relationship(end_node, "organization_has_domain", start_node))
    create_rel_cnt += 1
    print(f"create {create_rel_cnt} relations.")
# 生成组织和攻击手段的关联
with open('./ctiic/edge_organization_has_attacktype.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    start_node = node_matcer.match('organization', name=data[i][0]).first()
    end_node = node_matcer.match('attacktype', name=data[i][1]).first()
    graph.create(Relationship(start_node, "organization_has_attacktype", end_node))
    graph.create(Relationship(end_node, "organization_has_attacktype", start_node))
    create_rel_cnt += 1
    print(f"create {create_rel_cnt} relations.")
# 生成组织和攻击国家的关联
with open('./ctiic/edge_organization_has_area.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    start_node = node_matcer.match('organization', name=data[i][0]).first()
    end_node = node_matcer.match('area', name=data[i][1]).first()
    graph.create(Relationship(start_node, "organization_has_area", end_node))
    graph.create(Relationship(end_node, "organization_has_area", start_node))
    create_rel_cnt += 1
    print(f"create {create_rel_cnt} relation.")
# 生成组织和起源国家的关联
with open('./ctiic/edge_organization_from.csv', 'r', encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)
for i in range(1, len(data)):
    start_node = node_matcer.match('organization', name=data[i][0]).first()
    end_node = node_matcer.match('area', name=data[i][1]).first()
    graph.create(Relationship(start_node, "organization_from", end_node))
    graph.create(Relationship(end_node, "organization_from", start_node))
    create_rel_cnt += 1
    print(f"create {create_rel_cnt} relations.")
e_time = time.time()  # 停止计时
print(f"create {create_node_cnt} nodes, create {create_rel_cnt} relations.")  # 记录生成的节点数和关联数
print(f"cost time: {round((e_time - s_time) * 1000, 4)}ms")  # 计算时间
