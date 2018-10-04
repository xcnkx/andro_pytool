# coding:utf-8

import sys
import csv
import os.path
import collections

from tqdm import tqdm
from features_managment import *
from os.path import join as join_dir
from androguard.core.bytecodes import apk


############################################################
# MAIN METHOD
############################################################
def main():
    argvs = sys.argv
    argc = len(argvs)
    features_extractor(argvs[1], argvs[2], argvs[3])


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

    database = collections.OrderedDict()
    apk_analysis_list = []
    ROW = 0
    print "ANALYSING APKS..."
    for analyze_apk in tqdm(apk_list):
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
        opcodes_analysis_dict['ROW'] = ROW
        ROW += 1
        opcodes_analysis_dict['APK_name'] = apk_name_no_extensions

        opcodes_analysis_dict.update(opcodes_analysis(androguard_apk_object))

        opcodes_analysis_dict['STR_Opcodes'] = get_str_opcodes(androguard_apk_object)

        apk_analysis_list.append(opcodes_analysis_dict)

###EXPORT_TO_CSV#####
    if export_csv is not None:

        set_fields = set()

        export_csv = output_folder + "/" + export_csv

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



if __name__ == '__main__':
    main()
