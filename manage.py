#!/usr/local/bin/python

from pathlib import Path
import docker
import argparse
import sys


cwd = Path.cwd()
cwd_name = cwd.name
dockerfile_list = []


for child in cwd.iterdir():
    if child.name.startswith('Dockerfile'):
        target = child.name.rsplit('-', 1)
        if len(target) == 1:
            target.append('latest')

        dockerfile_list.append(target[-1])


client = docker.from_env()


parser = argparse.ArgumentParser(description='Docker helper tool for disastergram project')

subparsers = parser.add_subparsers()


build_parse = subparsers.add_parser('build', help='Build an image or images')
build_parse.add_argument('images',
                         choices=dockerfile_list + ['all'],
                         nargs='*',
                         default='latest',
                         help='A list of which image/s to build form these options {} \'all\' will build all images'.format(dockerfile_list))
build_parse.add_argument('--push',
                         action='store_true',
                         help='Push built images')


push_parse = subparsers.add_parser('push', help='Push images to docker.io')
push_parse.add_argument('images',
                        choices=dockerfile_list + ['all'],
                        nargs='*',
                        default='latest',
                        help='A list of which image/s to push push to docker.io form these options {} \'all\' will push every image'.format(dockerfile_list))


def push(args):
    images = args.images
    if 'all' in images:
        images = dockerfile_list

    for im in images:
        print('Pushing image: {}'.format(im))
        repo = 'dnikolaidis/{}'.format(cwd_name)
        image = client.images.get('{}:{}'.format(cwd_name, im))
        image.tag(repo, im)
        client.images.push(repo, im)


def build(args):
    images = args.images
    if 'all' in images:
        images = dockerfile_list

    push = args.push

    for im in images:
        dockerfile = 'Dockerfile'
        if im != 'latest':
            dockerfile += '-' + im
        
        print('Building image: {}'.format(im))

        image = client.images.build(path='.',
                                    dockerfile=dockerfile,
                                    tag='{}:{}'.format(cwd_name, im))

        if push:
            args = parser.parse_args(['push', im])
            args.func(args)


build_parse.set_defaults(func=build)

push_parse.set_defaults(func=push)

args = parser.parse_args()
if len(sys.argv) > 1:
    if isinstance(args.images, str):
        args.images = [args.images]

    args.func(args)
