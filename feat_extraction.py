import sys
import csv
import time
import bson
import json
import os.path
import hashlib
import argparse
import collections
import pandas as pd

from tqdm import tqdm
from os import listdir
from bson import json_util
from pymongo import MongoClient
from features_managment import *
from os.path import isdir, isfile
from collections import OrderedDict
from os.path import join as join_dir
from argparse import RawTextHelpFormatter
from androguard.core.bytecodes import apk
from avclass_caller import get_avclass_label


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


def features_extractor(apks_directory, output_folder, export_csv):


    """
    Extracts features from a set of samples

    Parameters
    ----------
    :param apks_directory: Folder containing apk files
    :param single_analysis: If an individual features file is generated for each sample
    :param dynamic_analysis_folder: Folder containing dynamic analysis reports
    :param virus_total_reports_folder: Folder containing VirusTotal reports
    :param flowdroid_folder: Folder containing flowdroid reports
    :param output_folder: Folder where features files are saved
    :param noclean_up: If unnecesary files generated are removed
    :param package_index_file: File describing Android API packages
    :param classes_index_file: File describing Android API classes
    :param system_commands_file: File describing Android system commands
    :param label: If provided, all samples are labelled according to this argument
    :param avclass: If avclass is executed to obtain a consensual label for each sample
    :param export_mongodb: Mongodb address to write features to a database
    :param export_csv: If the features extracted are saved into a csv file
    """
    source_directory = str(apks_directory)

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # # Load Android API packages and classes
    # global API_PACKAGES_LIST, API_CLASSES_LIST, API_SYSTEM_COMMANDS
    #
    # ############################################################
    # # READING PACKAGES, CLASSES AND SYSTEM COMMANDS
    # ############################################################
    # package_index_file = "info/package_index.txt"
    # classes_index_file = "info/class_index.txt"
    # system_commands_file = "info/system_commands.txt"
    #
    # package_file = load_file(str(package_index_file))
    # API_PACKAGES_LIST = [x.strip() for x in package_file]
    #
    # class_file = load_file(str(classes_index_file))
    # API_CLASSES_LIST = [x.strip() for x in class_file]
    #
    # system_commands_file = load_file(str(system_commands_file))
    # API_SYSTEM_COMMANDS = [x.strip() for x in system_commands_file]
    # ###########################################################

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
    apk_analysis_dic = collections.OrderedDict()

    print "ANALYSING APKS..."
    for analyze_apk in tqdm(apk_list):

        # Getting the name of the folder that contains all apks and folders with apks
        base_folder = source_directory.split("/")[-1]

        apk_filename = join_dir(base_folder, analyze_apk.replace(source_directory, ''))
        apk_filename = apk_filename.replace("//", "/")

        apk_name_no_extensions = "".join(apk_filename.split("/")[-1].split(".")[:-1])

        if os.path.isfile(join_dir(output_folder, apk_filename.split("/")[-1].replace('.apk', '-analysis.json'))):
            database[apk_filename.replace('.apk', '')] = json.load(open(join_dir(output_folder, apk_filename.split("/")[-1].
                                                                            replace('.apk', '-analysis.json'))))
            continue

        try:
            androguard_apk_object = apk.APK(analyze_apk)
        except Exception:
            print "ERROR in APK: " + apk_name_no_extensions
            continue

        static_analysis_dict = collections.OrderedDict()
        # Package name
        static_analysis_dict['Package name'] = androguard_apk_object.get_package()

        # # Permissions
        # static_analysis_dict['Permissions'] = androguard_apk_object.get_permissions()

        # Opcodes
        static_analysis_dict['Opcodes'] = opcodes_analysis(androguard_apk_object)
        # print static_analysis_dict['Opcodes'][1]
        # Activities
        # try:
        #     list_activities = androguard_apk_object.get_activities()
        # except UnicodeEncodeError:
        #     list_activities = []
        #
        # # Main activity
        # static_analysis_dict['Main activity'] = androguard_apk_object.get_main_activity()
        #
        # # Receivers
        # try:
        #     list_receivers = androguard_apk_object.get_receivers()
        # except UnicodeEncodeError:
        #     list_receivers = []
        #
        # # Services
        # try:
        #     list_services = androguard_apk_object.get_services()
        # except UnicodeEncodeError:
        #     list_services = []
        #
        # # API calls and Strings
        # list_smali_api_calls, list_smali_strings = read_strings_and_apicalls(analyze_apk, API_PACKAGES_LIST,
        #                                                                      API_CLASSES_LIST)
        # for api_call in list_smali_api_calls.keys():
        #     new_api_call = '.'.join(api_call.split(".")[:-1])
        #     if new_api_call in list_smali_api_calls.keys():
        #         list_smali_api_calls[new_api_call] = list_smali_api_calls[new_api_call] + list_smali_api_calls[api_call]
        #     else:
        #         list_smali_api_calls[new_api_call] = list_smali_api_calls[api_call]
        #         del list_smali_api_calls[api_call]
        # static_analysis_dict['API calls'] = list_smali_api_calls
        # static_analysis_dict['Strings'] = Counter(filter(None, list_smali_strings))
        #
        # # API packages
        #
        # API_packages_dict = collections.OrderedDict()
        # android_list_packages_lenghts = [len(x.split(".")) for x in API_PACKAGES_LIST]
        #
        # list_api_calls_keys = list_smali_api_calls.keys()
        # for api_call in list_api_calls_keys:
        #     score = 0
        #     package_chosen = None
        #     for i, package in enumerate(API_PACKAGES_LIST):
        #         len_package = android_list_packages_lenghts[i]
        #         if api_call.startswith(package) and len_package > score:
        #             score = len_package
        #             package_chosen = package
        #     if package_chosen is not None:
        #         if not package_chosen in API_packages_dict.keys():
        #             API_packages_dict[package_chosen] = list_smali_api_calls[api_call]
        #         else:
        #             API_packages_dict[package_chosen] += list_smali_api_calls[api_call]
        #
        # static_analysis_dict['API packages'] = API_packages_dict
        #
        #
        # # System commands
        # list_system_commands = read_system_commands(list_smali_strings, API_SYSTEM_COMMANDS)
        # static_analysis_dict['System commands'] = Counter(list_system_commands)
        #
        # # Intents
        # try:
        #     static_analysis_dict['Intents'] = intents_analysis(join_dir(analyze_apk.replace('.apk', ''),
        #                                                                 'AndroidManifest.xml'))
        # except:
        #     static_analysis_dict['Intents'] = {'Failed to extract intents': 0}
        #
        # # Intents of activities
        # intents_activities = collections.OrderedDict()
        # for activity in list_activities:
        #
        #
        #     intents_activities[activity] = check_for_intents(join_dir(analyze_apk.replace('.apk', ''),
        #                                                               'AndroidManifest.xml'),
        #                                                      activity, 'activity')
        # static_analysis_dict['Activities'] = intents_activities
        #
        # # Intents of services
        # intents_services = collections.OrderedDict()
        # for service in list_services:
        #     intents_services[service] = check_for_intents(join_dir(analyze_apk.replace('.apk', ''),
        #                                                            'AndroidManifest.xml'),
        #                                                   service, 'service')
        # static_analysis_dict['Services'] = intents_services
        #
        # # Intents of receivers
        # intents_receivers = collections.OrderedDict()
        # for intent in list_receivers:
        #     intents_receivers[intent] = check_for_intents(join_dir(analyze_apk.replace('.apk', '/'),
        #                                                            'AndroidManifest.xml'),
        #                                                   intent, 'receiver')
        # static_analysis_dict['Receivers'] = intents_receivers

        index = 0
        apk_analysis_dic[str(index)] = static_analysis_dict
        index += 1

    print apk_analysis_dic['0']['Opcodes'][1]
    #     ############################################################
#     # EXPORTING TO CSV
#     ############################################################
#     if export_csv is not None:
#
#         set_permissions = set()
#         set_opcodes = set()
#         set_apicalls = set()
#         set_systemcommands = set()
#         set_intents_activities = set()
#         set_intents_services = set()
#         set_intents_receivers = set()
#         set_api_packages = set()
#
#         print static_analysis_dict.keys()
#
#         for apk_key in tqdm(static_analysis_dict.keys()):
#             apk_dict = static_analysis_dict[apk_key]
#
#             set_permissions.update(apk_dict["Permissions"])
#             set_opcodes.update(apk_dict["Opcodes"])
#             set_apicalls.update(apk_dict["API calls"])
#             set_systemcommands.update(apk_dict["System commands"])
#
#             for activity in apk_dict["Activities"]:
#                 if apk_dict["Activities"][activity] is not None and \
#                     len(apk_dict["Activities"][activity]) > 0:
#                     set_intents_activities.update(apk_dict["Activities"][activity])
#
#             for service in apk_dict["Services"]:
#                 if apk_dict["Services"][service] is not None and \
#                     len(apk_dict["Services"][service]) > 0:
#                     set_intents_services.update(apk_dict["Services"][service])
#
#             for receiver in apk_dict["Receivers"]:
#                 if apk_dict["Receivers"][receiver] is not None and \
#                     len(apk_dict["Receivers"][receiver]) > 0:
#                     set_intents_receivers.update(apk_dict["Receivers"][receiver])
#
#             set_api_packages.update(apk_dict["API packages"])
#
#         list_permissions = [x.replace(" ", "") for x in list(set_permissions)]
#         list_opcodes = list(set_opcodes)
#         list_apicalls = list(set_apicalls)
#         list_systemcommands = list(set_systemcommands)
#         list_intents_activities = list(set_intents_activities)
#         list_intents_services = list(set_intents_services)
#         list_intents_receivers = list(set_intents_receivers)
#         list_api_packages = list(set_api_packages)
#
#         for i, apicall in enumerate(list(list_apicalls)):
#             list_apicalls[i] = ".".join(apicall.encode('ascii', 'ignore').split(".")[:-1])
#
#         list_apicalls = list(set(list_apicalls))
#
#         #
#         # flowdroid_fields = []
#         # if flowdroid_folder:
#         #     apk_dict_example = database[database.keys()[0]]
#         #     flowdroid_fields = apk_dict_example["Static_analysis"]["FlowDroid"].keys()
#         #     del flowdroid_fields[flowdroid_fields.index("Sources\\Sinks")]
#         #
#         # flowdroid_fields_matrix = [(x, y) for x in flowdroid_fields for y in flowdroid_fields]
#
#         list_rows = []
#
#         rows_permissions = []
#         rows_opcodes = []
#         rows_apicalls = []
#         rows_systemcommands = []
#         rows_intents_activities = []
#         rows_intents_services = []
#         rows_intents_receivers = []
#         rows_api_packages = []
#
#         for apk_key in tqdm(static_analysis_dict.keys()):
#             apk_dict = static_analysis_dict[apk_key]
#             label = apk_key.split("/")[0]
#             list_permissions_filled = [0 for x in range(len(list_permissions))]
#             for i, item in enumerate(list_permissions):
#                 if item.replace(" ", "") in apk_dict["Permissions"]:
#                     list_permissions_filled[i] = 1
#
#             list_opcodes_filled = [0 for x in range(len(list_opcodes))]
#             for i, item in enumerate(list_opcodes):
#                 if item in apk_dict["Opcodes"]:
#                     list_opcodes_filled[i] = apk_dict["Opcodes"][item]
#
#             list_apicalls_filled = [0 for x in range(len(list_apicalls))]
#             for i, item in enumerate(list_apicalls):
#                 if item in apk_dict["API calls"]:
#                     list_apicalls_filled[i] = apk_dict["API calls"][item]
#
#             list_systemcommands_filled = [0 for x in range(len(list_systemcommands))]
#             for i, item in enumerate(list_systemcommands):
#                 if item in apk_dict["System commands"]:
#                     list_systemcommands_filled[i] = apk_dict["Static_analysis"]["System commands"][item]
#
#             list_intents_activities_filled = [0 for x in range(len(list_intents_activities))]
#             for i, item in enumerate(list_intents_activities):
#                 if item in apk_dict["Activities"]:
#                     list_intents_activities_filled[i] = 1
#
#             list_intents_services_filled = [0 for x in range(len(list_intents_services))]
#             for i, item in enumerate(list_intents_services):
#                 if item in apk_dict["Services"]:
#                     list_intents_services_filled[i] = 1
#
#             list_intents_receivers_filled = [0 for x in range(len(list_intents_receivers))]
#             for i, item in enumerate(list_intents_receivers):
#                 if item in apk_dict["Receivers"]:
#                     list_intents_receivers_filled[i] = 1
#
#             list_api_packages_filled = [0 for x in range(len(list_api_packages))]
#             for i, item in enumerate(list_api_packages):
#                 if item in apk_dict["API packages"]:
#                     list_intents_receivers_filled[i] = 1
#
#             # flowdroid_fields_matrix_filled = [0 for x in range(len(flowdroid_fields_matrix))]
#             # flow_df = pd.read_csv("FlowDroid_processed/" + hash_app + ".csv")
#             # flow_df = flow_df.set_index("Sources\Sinks")
#             # for i, item in enumerate(flowdroid_fields_matrix):
#             #     source, sink = item[0], item[1]
#             #     flowdroid_fields_matrix_filled[i] = flow_df[source][sink]
#             complete_row = [label] + list_permissions_filled + list_opcodes_filled + list_apicalls_filled + \
#                         list_systemcommands_filled + list_intents_activities_filled + \
#                         list_intents_services_filled + list_intents_receivers_filled + list_api_packages_filled
#
#             rows_permissions.append(list_permissions_filled)
#             rows_opcodes.append(list_opcodes_filled)
#             rows_apicalls.append(list_apicalls_filled)
#             rows_systemcommands.append(list_systemcommands_filled)
#             rows_intents_activities.append(list_intents_activities_filled)
#             rows_intents_services.append(list_intents_services_filled)
#             rows_intents_receivers.append(list_intents_receivers_filled)
#             rows_api_packages.append(list_api_packages_filled)
#             list_rows.append(complete_row)
#
#         list_permissions = ["PERMISSION-" + x for x in list(list_permissions)]
#         list_opcodes = ["OPCODE-" + x for x in list(list_opcodes)]
#         list_apicalls = ["APICALL-" + x for x in list(list_apicalls)]
#         list_systemcommands = ["SYSTEMCOMMAND-" + x for x in list(list_systemcommands)]
#         list_intents_activities = ["ACTIVITY-" + x for x in list(list_intents_activities)]
#         list_intents_services = ["SERVICE-" + x for x in list(list_intents_services)]
#         list_intents_receivers = ["RECEIVER-" + x for x in list(list_intents_receivers)]
#         list_api_packages = ["APIPACKAGE-" + x for x in list(list_api_packages)]
#         #
#         # flowdroid_fields_matrix_strings = ["FLOWDROID-" + x[0] + "-" + x[1] for x in flowdroid_fields_matrix]
#
#         complete_list_fields = ["label"] + list_permissions + list_opcodes + list_apicalls + \
#                        list_systemcommands + list_intents_activities + list_intents_services + list_intents_receivers + \
#                        list_api_packages
#
#         with open(export_csv, 'wb') as csv_file:
#
#             csvwriter = csv.writer(csv_file, delimiter=",")
#             csvwriter.writerow(complete_list_fields)
#             print "WRITING CSV FILE..."
#             for row in tqdm(list_rows):
#                 csvwriter.writerow(row)
#
if __name__ == '__main__':
    main()
