from pathlib import Path
source=Path('inspect-on-mac.sh').read_text(encoding='utf-8')
old='selector_args=$(python3 ../../scripts/native_ui_shards.py selectors "$shard")'
new='selector_args="-only-testing:AutoTunnelUITests/AutoTunnelUITests/testAutoPinnedFirstWithCurrentMemberAndPing"'
assert source.count(old)==1
source=source.replace(old,new)
needle='-parallel-testing-enabled NO'
assert source.count(needle)==1
source=source.replace(needle,needle+' -test-iterations 8 -run-tests-until-failure')
start=source.index('if [ "$result" -eq 0 ]; then\n python3 scripts/native_ui_shards.py verify "$shard"')
end=source.index('test "$result" -eq 0',start)
source=source[:start]+source[end:]
Path('inspect-ping-only-on-mac.sh').write_text(source,encoding='utf-8',newline='\n')
