import argparse
import copy
import subprocess
import time
import os
from ledhntr import LEDHNTR

def git_pull(args, led):
    # If git flag is set, cd to args.dir and run `git pull`
    _log = led.logger
    # change directory
    abs_path = os.path.abspath(args.dir)
    os.chdir(abs_path)
    # git pull
    try:
        gitres = subprocess.run(
            ['git', 'pull'],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        _log.error(f"Error updating repository: {e}")
    _log.info(f"git pull result from {args.dir}: {gitres.stdout}")
    if gitres.stderr:
        _log.error(f"Error running git pull from {args.d}: {gitres.stderr}")

def run(args, led):
    _log = led.logger
    # Load storage plugin
    files = led.load_plugin('localfile_client')
    # Load YAML plugin
    yaml = led.load_plugin('yaml_client')
    # Get full path
    abs_path = os.path.abspath(args.dir)

    # If git flag set, run git pull on the YAML hunt dir
    if args.git:
        git_pull(args, led)
    yaml.set_path(abs_path)
    yaml.load_hunts()
    if args.id:
        one_hunt = []
        for hunt in yaml.hunts:
            if hunt['id']==args.id:
                one_hunt.append(hunt)
                break
        yaml.hunts = one_hunt
        if not yaml.hunts:
            _log.error(f"No hunt found with ID {args.id}")
        else:
            _log.info(f"Running {len(yaml.hunts)} specific hunt(s): {args.id}")
    if not args.force:
        yaml.check_threshold()
    for hunt in yaml.hunts:
        failed = False
        try:
            plugin=led.load_plugin(hunt['plugin'])
        except Exception as e:
            _log.error(f"Could not load {hunt['plugin']} for {hunt['id']} - {e}")
            failed = True
        if failed:
            continue
        # Build enrichment map
        plugin._gen_enrich_map()
        # Set the output location based on the YAML's output field
        files.set_path(path=f"{hunt['output']}/", db_name=hunt['id'])
        # Load the plugin configs for the endpoint we're about to hit
        api_conf = copy.deepcopy(plugin.api_confs.get(hunt['endpoint']))
        api_conf.paginate=True
        # Set hunt parameters
        for k, v in hunt[hunt['endpoint']].items():
            api_conf.params[k]=v

        all_things = []
        # @ Run the search
        res = plugin.search(api_conf=api_conf)

        for thing in res['things']:
            if thing not in all_things:
                all_things.append(thing)

        # Make Splunk-friendly chunks from the batch-results
        if not hasattr(plugin, 'chunk_results'):
            files.write_raw_json(res['raw_pages'], filename=f"{hunt['id']}-no_chunks-", append_date=True)
        else:
            chunks = plugin.chunk_results(res['raw_pages'], api_conf=api_conf)
            chunk_no = 1
            for chunk in chunks:
                files.write_raw_json(chunk, filename=f"{hunt['id']}-{chunk_no}_of_{len(chunks)}-", append_date=True)
                chunk_no+=1

        # Query and write each resulting IP
        for thing in all_things:
            if thing.label == 'ip' and thing.keyval:
                api_conf2 = copy.deepcopy(
                    plugin.api_confs.get(plugin.enrich_map['ip']['endpoints'][0])
                )
                api_conf2.params[api_conf2.param_query_key]=thing.keyval
                # @ Run the search
                detail_res = plugin.search(api_conf2)
                files.write_raw_json(
                    detail_res['raw'],
                    filename=f"{hunt['id']}-{thing.keyval}-",
                    append_date=True
                )

        # Update threshold to prevent additional runs prior to timer resetting
        yaml.update_lastrun(hunts=[hunt])
        _log.info(f"Hunt {hunt['id']} complete!")

    _log.info(f"All hunts complete! Going to sleep...")

def main():
    parser = argparse.ArgumentParser(
        description="Run regularly-scheduled YAML hunts"
    )
    parser.add_argument(
        '-d',
        '--dir',
        type=str,
        default="./hunts/",
        help="Directory where YAML hunts are located"
    )
    parser.add_argument(
        '-g',
        '--git',
        action="store_true",
        help="If set, runs git pull from the hunt directory before running hunts"
    )
    parser.add_argument(
        '-f',
        '--force',
        action='store_true',
        help="If set, ignores lastrun times for all hunts"
    )
    parser.add_argument(
        '--id',
        type=str,
        help="If specified, runs a single hunt based on hunt ID value."
    )

    args = parser.parse_args()
    # Re-run every 10 minutes as long as force isn't set
    led = LEDHNTR()
    if not args.force:
        while True:
            run(args, led)
            time.sleep(600)
    else:
        led.logger.info(f"--force flag set, so only running once!")
        run(args)

if __name__ == "__main__":
    main()