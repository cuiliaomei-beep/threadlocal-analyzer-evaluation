#!/bin/bash
# Runs one command under /usr/bin/time -v in its own session and samples the summed RSS of the whole session twice a second.
#   measure.sh <timeout-seconds> <command-script>
# Prints one line:  MEASURE rc=<exit> wall_s=<s> user_s=<s> sys_s=<s> maxrss_kb=<largest single process> peak_tree_kb=<largest summed RSS sampled>
#                   load_before=<1-minute load average of the host before the run> load_after=<the same after the run>
#                   host_cpu_s=<busy CPU seconds of all processes of the host during the run>
# The load average includes the load of the previous run of the measurement itself, so it cannot show whether OTHER work was
# running. host_cpu_s minus the CPU time of the command (user_s + sys_s) is the CPU time that other processes used during the
# run; a wall-clock time is comparable only if this difference is small.
# maxrss_kb is what getrusage reports (exact, but only the largest single process); peak_tree_kb covers multi-process tools
# such as Infer (sampled, so short spikes between two samples can be missed).
to=$1; cmd=$2
load0=$(cut -d" " -f1 /proc/loadavg)
# busy jiffies of all CPUs of the host: user nice system irq softirq steal (idle and iowait excluded)
busy() { awk 'NR==1 {print $2+$3+$4+$7+$8+$9}' /proc/stat; }
b0=$(busy)
tf=$(mktemp); sf=$(mktemp)
setsid bash -c 'echo $$ > "$0"; exec /usr/bin/time -v -o "$1" timeout "$2" bash "$3"' "$sf" "$tf" "$to" "$cmd" > "$cmd.out" 2>&1 &
pid=$!
peak=0
while kill -0 $pid 2>/dev/null; do
  sid=$(cat "$sf" 2>/dev/null)
  if [ -n "$sid" ]; then
    cur=$(ps -s "$sid" -o rss= 2>/dev/null | awk '{s+=$1} END {print s+0}')
    [ "${cur:-0}" -gt "$peak" ] && peak=$cur
  fi
  sleep 0.5
done
wait $pid
el=$(grep "Elapsed (wall clock)" "$tf" | sed 's/.*): //')
wall=$(echo "$el" | awk -F: '{ if (NF==3) print $1*3600+$2*60+$3; else print $1*60+$2 }')
user=$(grep "User time" "$tf" | awk '{print $NF}')
sys=$(grep "System time" "$tf" | awk '{print $NF}')
rss=$(grep "Maximum resident set size" "$tf" | awk '{print $NF}')
rc=$(grep "Exit status" "$tf" | awk '{print $NF}')
b1=$(busy); hz=$(getconf CLK_TCK)
host=$(awk -v a="$b0" -v b="$b1" -v h="$hz" 'BEGIN {printf "%.1f", (b-a)/h}')
load1=$(cut -d" " -f1 /proc/loadavg)
echo "MEASURE rc=${rc:-NA} wall_s=${wall:-NA} user_s=${user:-NA} sys_s=${sys:-NA} maxrss_kb=${rss:-NA} peak_tree_kb=$peak load_before=$load0 load_after=$load1 host_cpu_s=$host"
rm -f "$tf" "$sf"
