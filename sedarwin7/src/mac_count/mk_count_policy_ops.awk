BEGIN {
	printf "static struct mac_policy_ops mac_count_ops = {\n"
}

{
	if (NR != 1)
		printf ",\n"
	printf "\t.mpo_" $2
	cnt = 4 - int(length(".mpo_"$2) / 8);
	for (i = 0; i < cnt; i++)
		printf "\t"
	printf "= mac_count_" $2
}

END {
	printf "\n};\n"
}
