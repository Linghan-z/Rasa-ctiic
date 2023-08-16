import csv
import time
# with open('D:\\Knowledge_Graph_Data\\data\\vertex_organization.csv', 'r',encoding='utf-8') as f:
#     reader = csv.reader(f)
#     data = list(reader)
# str=""
# str2=""
# for i  in  range(1,len(data)):
#     str=str+"{value: '"+data[i][1]+"',label: '"+data[i][1]+"'}, "
#     str2 = str2 + "{value: '" + data[i][2] + "',label: '" + data[i][2] + "'}, "
# with open('D:\\Knowledge_Graph_Data\\data\\vertex_industry.csv', 'r',encoding='utf-8') as f:
#     reader = csv.reader(f)
#     data = list(reader)
#
#
# str=""
# for i  in  range(1,len(data)):
#     str=str+"{value: '"+data[i][0]+"',label: '"+data[i][0]+"'}, "

with open('D:\\Knowledge_Graph_Data\\data\\edge_organization_from.csv', 'r',encoding='utf-8') as f:
    reader = csv.reader(f)
    data = list(reader)


str=""
for i  in  range(1,len(data)):
    str=str+"{value: '"+data[i][1]+"',label: '"+data[i][1]+"'}, "
with open(r"D:\theme_selector.txt", "w", encoding='utf-8')as f:
    f.write(str)
