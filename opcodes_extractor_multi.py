# coding:utf-8

import sys
import csv

import os.path
import collections


from tqdm import tqdm

from features_managment import *

from os.path import join as join_dir

from androguard.core.bytecodes import apk

from multiprocessing import Pool
import multiprocessing


# ############################################################
# # VARIABLES
# ############################################################
# TIME_EXECUTION = str(time.time())
# API_PACKAGES_LIST = []
# API_CLASSES_LIST = []
# API_SYSTEM_COMMANDS = []
# OUTPUT_FILE_GLOBAL_JSON = "OUTPUT_ANDROPY_" + TIME_EXECUTION + ".json"
# OUTPUT_FILE_GLOBAL_CSV = "OUTPUT_ANDROPY_" + TIME_EXECUTION + ".csv"
#
# POSSIBLE_DYNAMIC_FILES_EXTENSIONS = [".csv", ".json", ".txt"]
# ############################################################



############################################################
# MAIN METHOD
############################################################
def main():
    argvs = sys.argv
    argc = len(argvs)
    features_extractor(argvs[1], argvs[2], argvs[3])

def multi(argsList, total):
    # p = Pool(multiprocessing.cpu_count() - 1) #最大プロセス数-1
    N = multiprocessing.cpu_count()-1

    p = Pool(N)
    output = list(tqdm(p.imap(wrapper, argsList), total=total))
    p.close()
    p.join()

    return output


def wrapper(args):

    return analyze_apks(*args)


def features_extractor(apks_directory, output_folder, export_csv):

    source_directory = str(apks_directory)

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    ############################################################
    # BUILDING LIST OF APKS
    ############################################################

    apk_list = list_files(source_directory, '*.apk')
    print '[*] Number of APKs:', len(apk_list)
    ############################################################

    ############################################################
    # ANALYSING APKS
    ############################################################

    print "ANALYSING APKS..."
    N = 500


    argsList = [(apk, source_directory) for apk in apk_list]
    argsList = sorted(argsList)

    total = len(argsList)

    N_argsList = [argsList[i:i+N] for i in range(0,total,N)]

    for nlist in tqdm(N_argsList):
        cnt = 0
        total = len(nlist)

        apk_analysis_list = multi((nlist), total)
        # for i in apk_analysis_list_temp:
        #     apk_analysis_list.append(i)


    ###EXPORT_TO_CSV#####
        if export_csv is not None:

            set_fields = set()

            export_csv = output_folder + "/" + export_csv + "_" + str(cnt) + ".csv"

            print "EXPORTING TO CSV:"
            print "RESOLVING FIELDS..."
            for row in tqdm(apk_analysis_list):
                apk_dict = row

                set_fields.update(apk_dict.keys())

            with open(export_csv, 'w') as f:

                list_fields = list(set_fields)

                fieldnames = list_fields
                fieldnames = sorted(fieldnames)
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                print "WRITING CSV ROWS..."
                for w in tqdm(apk_analysis_list):
                    writer.writerow(w)
            cnt += 1

def analyze_apks(analyze_apk, source_directory):
        # Getting the name of the folder that contains all apks and folders with apks
        base_folder = source_directory.split("/")[-1]

        apk_filename = join_dir(base_folder, analyze_apk.replace(source_directory, ''))
        apk_filename = apk_filename.replace("//", "/")

        apk_name_no_extensions = "".join(apk_filename.split("/")[-1].split(".")[:-1])

        try:
            androguard_apk_object = apk.APK(analyze_apk)
        except Exception:
            print "ERROR in APK: " + apk_name_no_extensions

        opcodes_analysis_dict = collections.OrderedDict()

        # Opcodes
        opcodes_analysis_dict['APK_name'] = apk_name_no_extensions

        opcodes_analysis_dict.update(opcodes_analysis(androguard_apk_object))

        opcodes_analysis_dict['STR_Opcodes'] = get_str_opcodes(androguard_apk_object)

        return opcodes_analysis_dict




if __name__ == '__main__':
    main()
