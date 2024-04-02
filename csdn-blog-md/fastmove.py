import os
import re

def change_pic():
    all_files = os.listdir('../source/_posts/')
    all_files.sort()
    all_files = [a for a in all_files if not a.endswith("md")]
    print(all_files)
    for a in all_files:
        f = open("../source/_posts/" + a + ".md", 'r')
        content = f.read()
        pics = re.findall('!\\[]\\(.+\\)', content)
        for i in range(len(pics)):
            photo = pics[i][4:-1]
            suffix = re.split('\\.', photo)[-1]
            command = "wget " + photo + " -O ../source/_posts/" + a + "/" + str(i+1) + "." + suffix
            print(command)
            os.system(command)
            content = content.replace(photo, str(i+1) + "." + suffix)
        f.close()
        f = open("../source/_posts/" + a + ".md", 'w')
        f.write(content)
        f.close()

if __name__ == '__main__':
    change_pic()
    # filelist = os.listdir('.')
    # for f in filelist:
    #     if not f.endswith('.md'):
    #         filelist.remove(f)
    # filelist = [f[:-3] for f in filelist]
    #
    # for f in filelist:
    #     os.system("hexo new \"" + f + '\"')
    #     file = open(f + '.md', 'r')
    #     content = file.read()
    #     md_filename = f.replace('(', ' ').replace(')', '').replace('  ', ' ').replace(' ', '-').replace('.', '-').replace('_', '-')
    #     output = open('../source/_posts/' + md_filename + '.md', 'a')
    #     output.write(content)
    #     file.close()
    #     output.close()