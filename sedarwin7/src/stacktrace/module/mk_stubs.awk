{
	printf "static " $1 "\n"
	printf "stacktrace_" $2
	for (i = 3; i <= NF; i++) {
		printf "%s ", $i
	}
	printf "\n{\n"
	printf "\ttrace(&" $2 "_td);\n"
	if ($1 == "int") {
		printf "\treturn (0);\n"
	}
	printf "}\n\n"
}
