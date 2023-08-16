from typing import Any, Text, Dict, List
from datetime import datetime, timedelta

from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher
import json
import time

from py2neo import Graph
from py2neo import NodeMatcher, RelationshipMatcher

url = "bolt://localhost:7687"
username = "neo4j"
password = "Neo4j"
graph = Graph(url, auth=(username, password))
node_matcer = NodeMatcher(graph)
relationship_matcher = RelationshipMatcher(graph)


##组织
class ActionRequestNetwork(Action):
    def name(self) -> Text:
        return "action_answer_brief"  # 对应domain.yml的动作名称

    def run(
            self,
            dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:
        og_name = tracker.get_slot("organization")  # 提取组织槽位名称“组织名”
        temp = tracker.get_slot("attribute")  # 提取组织节点的属性槽位名称
        if temp == "简介" or temp == "什么":  # 根据属性槽位名称，转换得到对应Neo4j的属性
            attribute = "introduction"
        elif temp == "出现时间":
            attribute = "occurtime"
        elif temp == "目的":
            attribute = "motivation"
        elif temp == "链接":
            attribute = "referlink"
        else:
            attribute = "introduction"
        # pattern = '.*'.join(name)
        # pattern = '.*'+pattern+'.*'
        find_node = node_matcer.match("organization").where(name=og_name).first()  # 根据组织名查找节点

        if find_node is None:  # 如果找不到
            dispatcher.utter_message(text="没找到'{}'".format(og_name))  # 反馈找不到
        else:
            # 如果找到了，反馈json格式的节点信息，按照“具体回答”（问答对话），类型，简介，出现时间，动机，链接
            dispatcher.utter_message(
                text='{"answer":"' + find_node[attribute] + '","type":"organization","introduction":"' + find_node[
                    "introduction"] + '","occurtime":"' + find_node["occurtime"] + '","motivation":"' + find_node[
                         "motivation"] + '","referlink":"' + find_node["referlink"] + '"}')
            # 查询该组织的关联sha256文件
            relationship = list(relationship_matcher.match([find_node], r_type="organization_has_sha256"))
            str1 = '['
            for i in relationship:
                str1 = str1 + '{sha_name:"' + i.end_node['name'] + '",sha_type:"' + i.end_node[
                    'type'] + '",sha_value:"' + i.end_node['value'] + '"},'
            str1 = str1.strip(',')
            str1 = str1 + ']'
            if str1 == '[]':
                str1 = '[{sha_name:"",sha_type:"",sha_value:""}]'
            dispatcher.utter_message(text=str1)  # 反馈该组织的关联sha256文件
            # 查询该组织的关联ip
            relationship = list(relationship_matcher.match([find_node], r_type="organization_has_ip"))
            str1 = '['
            for i in relationship:
                str1 = str1 + '{ip_name:"' + i.end_node['name'] + '",ip_value:"' + i.end_node['value'] + '"},'
            str1 = str1.strip(',')
            str1 = str1 + ']'
            if str1 == '[]':
                str1 = '[{ip_name:"",ip_value:""}]'
            dispatcher.utter_message(text=str1)  # 反馈该组织的关联ip
            # 查询该组织关联的产业
            relationship = list(relationship_matcher.match([find_node], r_type="organization_has_industry"))
            str1 = ''
            for i in relationship:
                str1 = str1 + i.end_node['name'] + ','
            str1 = str1.strip(',')
            if str1 == '':
                str1 = '未知'
            dispatcher.utter_message(text=str1)  # 反馈该组织关联的产业
            # 查询该组织关联的域名
            relationship = list(relationship_matcher.match([find_node], r_type="organization_has_domain"))
            str1 = '['
            for i in relationship:
                str1 = str1 + '{domain_name:"' + i.end_node['name'] + '",domain_value:"' + i.end_node['value'] + '"},'
            str1 = str1.strip(',')
            str1 = str1 + ']'
            if str1 == '[]':
                str1 = '[{domain_name:"",domain_value:""}]'
            dispatcher.utter_message(text=str1)  # 反馈该组织关联的域名
            # 查询该组织关联的攻击手段
            relationship = list(relationship_matcher.match([find_node], r_type="organization_has_attacktype"))
            str1 = '['
            for i in relationship:
                str1 = str1 + '{attacktype_name:"' + i.end_node['name'] + '",attacktype_value:"' + i.end_node[
                    'introduction'] + '"},'
            str1 = str1.strip(',')
            str1 = str1 + ']'
            if str1 == '[]':
                str1 = '[{attacktype_name:"",attacktype_value:""}]'
            dispatcher.utter_message(text=str1)  # 反馈该组织关联的攻击手段
            # 查询该组织关联的攻击国家
            relationship = list(relationship_matcher.match([find_node], r_type="organization_has_area"))
            str1 = ''
            for i in relationship:
                str1 = str1 + i.end_node['name'] + ','
            str1 = str1.strip(',')
            if str1 == '':
                str1 = '未知'
            dispatcher.utter_message(text=str1)  # 反馈该组织关联的攻击国家
            # 查询该组织关联的起源国家
            relationship = list(relationship_matcher.match([find_node], r_type="organization_from"))
            str1 = ''
            for i in relationship:
                str1 = str1 + i.end_node['name'] + ','
            str1 = str1.strip(',')
            if str1 == '':
                str1 = '未知'
            dispatcher.utter_message(text=str1)  # 反馈该组织关联的起源国家
            dispatcher.utter_message(text=og_name)  # 反馈该组织组织名
        return []


##攻击类型
class ActionRequestattacktype(Action):
    def name(self) -> Text:
        return "action_query_attacktype"  # 对应domain.yml的动作名称

    def run(
            self,
            dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:
        name = tracker.get_slot("attacktype")  # 提取槽位攻击手段的名称
        find_node = node_matcer.match("attacktype").where(name=name).first()  # 查询该攻击手段的名称的节点
        if find_node is None:
            dispatcher.utter_message(text="没找到'{}'".format(name))  # 查如果找不到
        else:
            # 反馈具体回答，以及该节点所有节点属性，以json
            dispatcher.utter_message(
                text='{"answer":"' + find_node["introduction"] + '","type":"attacktype","introduction":"' + find_node[
                    "introduction"] + '"}')
            relationship = list(
                relationship_matcher.match([find_node], r_type="organization_has_attacktype"))  # 查询该攻击手段关联的组织节点
            str1 = '['
            for i in relationship:
                str1 = str1 + '{organization_name:"' + i.end_node['name'] + '",organization_introduction:"' + \
                       i.end_node['introduction'] + '"},'
            str1 = str1.strip(',')
            str1 = str1 + ']'
            dispatcher.utter_message(text=str1)  # 反馈该攻击手段关联的组织节点
        return []


##域
class ActionRequestdomain(Action):
    def name(self) -> Text:
        return "action_query_domain"  # 对应domain.yml的动作名称

    def run(
            self,
            dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:
        name = tracker.get_slot("domain")  # 提取槽位域名的名称
        find_node = node_matcer.match("domain").where(name=name).first()  # 查询该域名的名称的节点
        if find_node is None:
            dispatcher.utter_message(text="没找到'{}'".format(name))  # 查如果找不到
        else:
            dispatcher.utter_message(
                text='{"answer":"' + find_node["value"] + '","type":"domain","value":"' + find_node["value"] + '"}')
            relationship = list(
                relationship_matcher.match([find_node], r_type="organization_has_domain"))  # 查询该域名关联的组织节点
            str1 = '['
            for i in relationship:
                str1 = str1 + '{organization_name:"' + i.end_node['name'] + '",organization_introduction:"' + \
                       i.end_node['introduction'] + '"},'
            str1 = str1.strip(',')
            str1 = str1 + ']'
            dispatcher.utter_message(text=str1)  # 反馈该域名关联的组织节点

        return []


##ip
class ActionRequestip(Action):
    def name(self) -> Text:
        return "action_query_ip"  # 对应domain.yml的动作名称

    def run(
            self,
            dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:
        name = tracker.get_slot("ip")  # 提取槽位ip的名称
        find_node = node_matcer.match("ip").where(name=name).first()  # 查询该ip的名称的节点
        if find_node is None:
            dispatcher.utter_message(text="没找到'{}'".format(name))  # 查如果找不到
        else:
            dispatcher.utter_message(
                text='{"answer":"' + find_node["value"] + '","type":"ip","value":"' + find_node["value"] + '"}')
            relationship = list(relationship_matcher.match([find_node], r_type="organization_has_ip"))  # 查询该ip关联的组织节点
            str1 = '['
            for i in relationship:
                str1 = str1 + '{organization_name:"' + i.end_node['name'] + '",organization_introduction:"' + \
                       i.end_node['introduction'] + '"},'
            str1 = str1.strip(',')
            str1 = str1 + ']'
            dispatcher.utter_message(text=str1)  # 反馈该ip关联的组织节点
        return []


##sha256
class ActionRequestip(Action):
    def name(self) -> Text:
        return "action_query_sha256"  # 对应domain.yml的动作名称

    def run(
            self,
            dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:
        name = tracker.get_slot("sha256")  # 提取槽位哈希文件的名称
        temp = tracker.get_slot("attribute")  # 提取槽位哈希文件的属性
        if temp == "值" or temp == "什么" or temp == "哈希值":  # 根据槽位哈希文件的槽位，转换成哈希文件在Neo4j中的属性
            attribute = "value"
        elif temp == "什么文件" or temp == "什么类型文件":
            attribute = "type"
        find_node = node_matcer.match("sha256").where(name=name).first()  # 查询该哈希文件的名称的节点
        if find_node is None:
            dispatcher.utter_message(text="没找到'{}'".format(name))  # 查如果找不到
        else:
            dispatcher.utter_message(
                text='{"answer":"' + find_node[attribute] + '","type":"sha256","value":"' + find_node[
                    "value"] + '","type2":"' + find_node["type"] + '"}')
            relationship = list(relationship_matcher.match([find_node], r_type="organization_has_sha256"))
            str1 = '['
            for i in relationship:
                str1 = str1 + '{organization_name:"' + i.end_node['name'] + '",organization_introduction:"' + \
                       i.end_node['introduction'] + '"},'
            str1 = str1.strip(',')
            str1 = str1 + ']'
            dispatcher.utter_message(text=str1)  # 反馈该哈希文件的名称的节点
        return []


# 起源国家的病毒组织
class ActionRequestip(Action):
    def name(self) -> Text:
        return "action_query_from"  # 对应domain.yml的动作名称

    def run(
            self,
            dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:
        name = tracker.get_slot("area")  # 提取槽位area的名称
        find_node = node_matcer.match("area").where(name=name).first()  # 查询该area的名称的节点
        if find_node is None:
            dispatcher.utter_message(text="没找到'{}'".format(name))  # 如果查找不到
        else:
            relationship = list(relationship_matcher.match([find_node], r_type="organization_from"))  # 查询该ip关联的组织节点
            str1 = '['
            for i in relationship:
                str1 = str1 + i.end_node['name'] + ','
            str1 = str1.strip(',')
            str1 = str1 + ']'
            if str1 == '[]':
                dispatcher.utter_message(text="不存在组织起源于'{}'".format(name))  # 查如果找不到
            else:
                dispatcher.utter_message(text=str1)  # 反馈该area关联的组织节点
        return []


# 攻击国家的病毒组织
class ActionRequestip(Action):
    def name(self) -> Text:
        return "action_query_attack"  # 对应domain.yml的动作名称

    def run(
            self,
            dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:
        name = tracker.get_slot("area")  # 提取槽位area的名称
        find_node = node_matcer.match("area").where(name=name).first()  # 查询该area的名称的节点
        if find_node is None:
            dispatcher.utter_message(text="没找到'{}'".format(name))  # 如果查找不到
        else:
            relationship = list(relationship_matcher.match([find_node], r_type="organization_has_area"))  # 查询该ip关联的组织节点
            str1 = '['
            for i in relationship:
                str1 = str1 + i.end_node['name'] + ','
            str1 = str1.strip(',')
            str1 = str1 + ']'
            if str1 == '[]':
                dispatcher.utter_message(text="不存在组织攻击'{}'".format(name))  # 查如果找不到
            else:
                dispatcher.utter_message(text=str1)  # 反馈该area关联的组织节点
        return []


# 使用某种攻击类型的组织
class ActionRequestip(Action):
    def name(self) -> Text:
        return "action_query_org_via_attacktype"  # 对应domain.yml的动作名称

    def run(
            self,
            dispatcher: CollectingDispatcher,
            tracker: Tracker,
            domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:
        name = tracker.get_slot("attacktype")  # 提取槽位attacktype的名称
        find_node = node_matcer.match("attacktype").where(name=name).first()
        if find_node is None:
            dispatcher.utter_message(text="没找到'{}'".format(name))
        else:
            relationship = list(relationship_matcher.match([find_node], r_type="organization_has_attacktype"))
            str1 = '['
            for i in relationship:
                str1 = str1 + i.start_node['name'] + ','
            str1 = str1.strip(',')
            str1 = str1 + ']'
            if str1 == '[]':
                dispatcher.utter_message(text="不存在使用'{}'的组织".format(name))
            else:
                dispatcher.utter_message(text=str1)
        return []
