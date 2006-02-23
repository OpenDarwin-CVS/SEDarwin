{
	printf "static " $1 "\n"
	printf "mac_count_" $2
	for (i = 3; i <= NF; i++) {
		printf "%s ", $i
	}
	printf "\n{\n"
	printf "\tINC(" $2 ");\n"
	if ($1 == "int") {
		printf "\tRET(" $2 ");\n"
	}
	printf "}\n\n"
}
