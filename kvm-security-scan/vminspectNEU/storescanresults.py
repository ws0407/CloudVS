import json
import time
import os


def store_scan_results(arguments, results):
    # file output specific code
    outputDict = {}
    workloadStartIndex = arguments.disk.find('/workload')
    INPUT_FILE_NAME = arguments.disk.replace("/", "_")
    timestr = time.strftime("%Y%m%d-%H%M%S")
    if workloadStartIndex != -1:
        workloadString = arguments.disk[workloadStartIndex:]
        splitlist = workloadString[1:].split('/')
        INPUT_FILE_NAME = "vm_" + splitlist[4]
        snapshotPath = arguments.disk[:arguments.disk.find("/vm_id")]
    else:
        snapshotPath = os.getcwd()

    outFilePath = snapshotPath + "/scans/"
    if not os.path.exists(outFilePath):
        try:
            os.makedirs(outFilePath)
        except OSError as err:
            raise err
    outFilePath = outFilePath + INPUT_FILE_NAME + "_" + timestr

    if results is not None:
        # embed json results in dict
        resultDict  = {"results": results}
        outputDict.update(resultDict)
        print("############save scanning result to: " + outFilePath + "#############")
        with open(outFilePath, 'w+') as outfile:
            outfile.write(json.dumps(outputDict, indent=4))
            outfile.write(results)

