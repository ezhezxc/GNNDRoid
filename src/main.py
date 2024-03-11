#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import logging
import os
import shutil
import argparse
import psutil
import multiprocessing as mp
import math

from cfg_java import *
from cfg_so import *

from relations_abstract import RelationAbstract
from graphs_merge import GraphMerging
from nodes_vectorize import GetGMLof2Parts
from store_native_and_java_gmls import StoreGMLsForAPK
    
def process_single_apk(apk, apk_path, tmp_path, graphs_path, good_or_mal, process_id):
    
    logging.info("----------------------------------开始处理{} apk：{} ----- 进程{}".format(good_or_mal, apk, process_id))
    if not os.path.exists(tmp_path):
        os.mkdir(tmp_path)
        
    if not os.path.exists(graphs_path):
        os.mkdir(graphs_path)
    
    logging.info("正在生成apk {} 的Java CFGs".format(apk))
    JAVA_CFG = GenJavaCFG(apk_path, tmp_path)

    logging.info("正在生成apk {} 的Native CFGs".format(apk))
    so_path = JAVA_CFG.decompile_path
    Native_CFG = GenSOCFG(so_path, tmp_path, process_id)

    os.system("ps -ef | grep r2 | awk '{print $2;}' | xargs kill -9")

    logging.info("RelationshipsAbstract...")
    gml_path = GetGMLof2Parts(tmp_path).node_vec_path

    relations_abstract = RelationAbstract(tmp_path, gml_path)
    relations_path = relations_abstract.relations_path

    logging.info("GraphMerging...")
    GraphMerging(relations_path, gml_path, graphs_path, apk)
    
    
    dst_path = os.path.join(r"graphs_to_train", good_or_mal, apk)

    StoreGMLsForAPK(gml_path, dst_path)
    
    logging.debug("----------------------------------apk {} 图生成成功，删除tmp文件".format(apk))
    if os.path.exists(tmp_path):
        shutil.rmtree(tmp_path)

def processing_all_apks(TmpPath, OutputPath, dir, index, apk_list):
    logging.info("processing_all_apks begin dir {}  index {} apk_list_size {}".format(dir, index, len(apk_list)))
    for apk in apk_list:
        logging.info("111111111111111111111111111111111111 {} {}".format(index, apk))
        apk_path = os.path.join(dir, apk)
        classification = os.path.basename(dir) #是malware还是benign
        dst_gml_path = os.path.join(OutputPath, classification, apk[:-4] + '.gml')
        
        #process_id = str(os.getpid())
        process_id = str(index)
        tmp_path = TmpPath + process_id
        
        if os.path.exists(dst_gml_path):
            logging.info("----------------------------------apk {}已生成图".format(apk))
            continue
        
        else:
            try:
                process_single_apk(apk[:-4], apk_path, \
                tmp_path=tmp_path, graphs_path=os.path.join(OutputPath, classification),\
                    good_or_mal = classification, process_id = process_id)
            except Exception as e:
                logging.error("{} -- 失败,原因{}".format(apk, e))
                if os.path.exists(tmp_path):
                    shutil.rmtree(tmp_path)
                continue

def addProcess(TmpPath, OutputPath, dir, ProcessNumber, startIndex = 0):
    process_list = []
    total_apk_list = os.listdir(dir)
    apk_counts = len(total_apk_list)   # 总apk数
    deal_num = int(math.ceil(apk_counts/ProcessNumber)) # 单个进程处理apk个数，总apk个数除以进程数
    # n号进程处理[n * 单进程分片数, (n * 单进程分片数)+单进程分片数 )
    for i in range(0, ProcessNumber):
        start = i*deal_num
        end = (i + 1)*deal_num
        if (end > apk_counts):
            # 防止溢出
            end = apk_counts
        
        logging.info("dir{} start {} end {}".format(dir, start, end))
        apk_list = total_apk_list[start: end]
        p = mp.Process(target=processing_all_apks, args=(TmpPath, OutputPath, dir, (startIndex + i), apk_list))
        p.start()
        process_list.append(p)
    return process_list

def main(Args):
    # 配置日志文件和日志级别
    LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    DATE_FORMAT = "%m/%d/%Y %H:%M:%S %p"
    
    logging.basicConfig(filename='my.log', level=logging.DEBUG, format=LOG_FORMAT, datefmt=DATE_FORMAT)

    MalDir = Args.maldir
    GoodDir= Args.gooddir
    OutputPath = Args.output_path
    if not os.path.exists(OutputPath):
        os.mkdir(OutputPath)

    TmpPath = Args.tmp_path

    ProcessNumber = Args.ncpucores
    process_list = []

    # 处理gooddir
    process_list += addProcess(TmpPath, OutputPath, GoodDir, ProcessNumber)

    # 处理maldir
    process_list += addProcess(TmpPath, OutputPath, MalDir, ProcessNumber, ProcessNumber)

    for process in process_list:
        process.join()
    
def ParseArgs():
    Args = argparse.ArgumentParser(description="Input APKs and Output GMLs of Android Applications.")
    
    Args.add_argument("--maldir", default="apks/malware", help="Path to directory containing malware apks.")
    Args.add_argument("--gooddir", default="apks/benign", help="Path to directory containing benign apks.")
    Args.add_argument("--ncpucores", type= int, default= psutil.cpu_count(),help= "Number of CPUs that will be used for processing")
    Args.add_argument("--output_path", default="graphs", help="Path to directory of output graphs.")
    Args.add_argument("--tmp_path", default="tmp", help="Path to directory for temperary files.")
    
    return Args.parse_args()

if __name__ == "__main__":
    main(ParseArgs())