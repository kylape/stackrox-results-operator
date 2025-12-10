#!/usr/bin/env python3

import json
import os
import randomname
import shutil

os.makedirs("obfuscated", exist_ok=True)

cache = {}

def obfuscate(obj, key):
    original = obj[key]
    if original not in cache:
        cache[original] = randomname.get_name()

    obj[key] = cache[original]

with open("src/alerts.json") as fp:
    with open("obfuscated/alerts.json", "w") as obf:
        alerts_json = json.load(fp)
        for i, alert in enumerate(alerts_json["alerts"]):
            obfuscate(alert["deployment"], "namespace")
            obfuscate(alert["deployment"], "clusterName")
        json.dump(alerts_json, obf)

with open("src/clusters.json") as fp:
    with open("obfuscated/clusters.json", "w") as obf:
        clusters_json = json.load(fp)
        for i, cluster in enumerate(clusters_json["clusters"]):
            obfuscate(cluster, "name")
        json.dump(clusters_json, obf)

with open("src/nodes.json") as fp:
    with open("obfuscated/nodes.json", "w") as obf:
        nodes_json = json.load(fp)
        for i, node in enumerate(nodes_json["nodes"]):
            obfuscate(node, "name")
            obfuscate(node, "clusterName")
            del node["labels"]
        json.dump(nodes_json, obf)

with open("src/deployments.ndjson") as fp:
    with open("obfuscated/deployments.ndjson", "w") as obf:
        for line in fp.readlines():
            deploy_json = json.loads(line)
            deploy = deploy_json["result"]["deployment"]
            obfuscate(deploy, "clusterName")
            obfuscate(deploy, "name")
            obfuscate(deploy, "namespace")
            del deploy["podLabels"]
            del deploy["labelSelector"]
            del deploy["labels"]
            json.dump(deploy_json, obf)
            obf.write("\n")

shutil.copy("src/images.ndjson", "obfuscated/images.ndjson")
