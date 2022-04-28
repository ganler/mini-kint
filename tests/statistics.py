import os
import re
from sklearn.metrics import precision_recall_fscore_support as score
from sklearn.metrics import classification_report

def statistics(path):
    if not os.path.exists(path):
        print(f'== Error: log file [{path}] not exist')
        exit(0)

    LOG=open(path).read()

    result_map = {}
    count_map = {}
    Y0 = "no error"
    Y1 = "error"

    correct = 0
    total = 0

    for id, line in enumerate(LOG.split('\n')):
        suffix = ": MKintPass :: [a-zA-Z0-9\-\_\/]+.c"
        found = re.findall(f"^FAIL{suffix}|PASS{suffix}", line)
        if (len(found) != 0):
            found = found[0]
            result = found.split(':')[0]
            file = found.split(' ')[-1].split('.')[0]
            test_type, filename = file.split('/')
            
            print(f'{result} in testing {test_type} : {filename}')

            if test_type not in result_map:
                # [predicted, y_test]
                result_map[test_type] = [[], []]
                count_map[test_type] = [0, 0]
            
            predicted = None
            y_test = None
            total += 1
            count_map[test_type][1] += 1

            if result == "PASS":
                correct += 1
                count_map[test_type][0] += 1
                if 'none' in filename:
                    y_test = Y0
                    predicted = Y0
                else:
                    y_test = Y1
                    predicted = Y1

            if result == "FAIL": 
                if 'none' in filename:
                    y_test = Y0
                    predicted = Y1
                else:
                    y_test = Y1
                    predicted = Y0

            result_map[test_type][0].append(predicted)
            result_map[test_type][1].append(y_test)
    
    predicted_total = []
    y_test_total = []
    for k, v in result_map.items():
        predicted, y_test = v
        predicted_total += predicted
        y_test_total += y_test
        # print(f'== k : {k}')
        # precision, recall, fscore, support = score(y_test, predicted)

        # print('precision: {}'.format(precision))
        # print('recall: {}'.format(recall))
        # print('fscore: {}'.format(fscore))
        # print('support: {}'.format(support))

    type_set = set(result_map.keys())
    for t in type_set:
        print(f"\n== {t}: {count_map[t][0]}/{count_map[t][1]} = {count_map[t][0]/count_map[t][1]}\n")

    precision, recall, fscore, support = score(y_test_total, predicted_total)
    print(f"\n== totally: {correct}/{total} = {correct/total}\n")
    print('precision: {}'.format(precision))
    print('recall: {}'.format(recall))
    print('fscore: {}'.format(fscore))
    print('support: {}'.format(support))
    

if __name__ == '__main__':
    
    print("Usage: LOG=<path_to_log> python3 statistics.py")
    statistics(os.environ['LOG'])
    
