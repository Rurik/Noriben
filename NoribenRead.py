import argparse
import sys
import zipfile


exts = ('txt', 'csv')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Noriben Report Archive', required=True)
    parser.add_argument('-l', '--log', help='File archive to read ("txt", "csv", or filename)', required=True)

    args = parser.parse_args()
    fname = ''
    if not args.log in exts:
            fname = args.log

    archive = zipfile.ZipFile(args.file)
    if '_NoribenReport.zip' not in args.file:
        quit()

    #fname = args.file.replace('NoribenReports_', '').replace('.zip', '')
    contents = ''
    for fn in archive.namelist():
        print(fn, args.log)
        if not fname:
            if fn.startswith('Noriben') and fn.endswith(args.log):
                txt = archive.open(fn, 'r')
                contents = txt.read()
                break
        else:
            if fn == fname:
                txt = archive.open(fn, 'r')
                contents = txt.read()
                break
    if not contents:
        print('ERROR')

    for line in contents.split('\n'):
        print(line)
        #if 'CreateProcess' in line and ('vss' in line.lower() or 'wmic' in line.lower()):


if __name__ == '__main__':
    main()
