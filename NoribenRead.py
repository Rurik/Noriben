import argparse
import glob
import os
import sys
import zipfile


exts = ('txt', 'csv')

def search_archive(args):
    fname = ''
    if not args.log in exts:
        fname = args.log

    archive_name = '{}/{}'.format(args.file.split(os.sep)[-2], args.file.split(os.sep)[-1].split('_Noriben')[0])

    if '_NoribenReport.zip' not in args.file:  #TODO: This is a hack
        return

    try:
        archive = zipfile.ZipFile(args.file)
    except zipfile.BadZipfile:
        return

    contents = ''
    for fn in archive.namelist():
        if not fname:
            if fn.startswith('Noriben') and fn.endswith(args.log):
                txt = archive.open(fn, 'r')
                contents = txt.readlines()
                break
        else:
            if fn == fname:
                txt = archive.open(fn, 'r')
                contents = txt.readlines()
                break
    if not contents:
    #    print('[!] {} not found in archive {}'.format(args.log, args.file))
        return 1

    resultsFound = False
    for line in contents:
        line = unicode(line.strip())
        if args.search:
            #args.search = bytes(mystring, 'utf-8')
            if args.insensitive:
                if args.search.lower() in line.lower():
                    resultsFound = True
                    if args.hide:
                        print(line)
                    else:
                        print('{}: {}'.format(archive_name, line.strip()))
            elif args.search in line:
                resultsFound = True
                if args.hide:
                    print(line)
                else:
                    print('{}: {}'.format(archive_name, line.strip()))
        else:
            print(line)

    #if not resultsFound:
    #    print('{}: Not blocked by Defense!'.format(archive_name))
        #if 'CreateProcess' in line and ('vss' in line.lower() or 'wmic' in line.lower()):



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Noriben Report Archive', required=False)
    parser.add_argument('-d', '--dir', help='Noriben Report Archive Folder', required=False)
    parser.add_argument('--recursive', action='store_true', help='Recursive', required=False)
    parser.add_argument('-l', '--log', help='File archive to read ("txt", "csv", or filename)', required=True)
    parser.add_argument('-s', '--search', help='Search term in output', required=False)
    parser.add_argument('--hide', action='store_true', help='Hide filename', required=False)
    parser.add_argument('-i', '--insensitive', action='store_true', help='Search term as case insensitive', required=False)

    args = parser.parse_args()
    files = list()

    if not args.file and not args.dir:
        print('You\'re holding it wrong')
        sys.exit(1)

    if args.file:
        search_archive(args)
        sys.exit(0)
    elif args.dir:
        for result in glob.iglob(args.dir):
            for (root, subdirs, filenames) in os.walk(result):
                for fname in filenames:
                    files.append(os.path.join(root, fname))

                if not args.recursive:
                    break

        for file in files:
            args.file = file
            search_archive(args)



if __name__ == '__main__':
    main()
