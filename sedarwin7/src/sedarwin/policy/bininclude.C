
#include <stdio.h>

int main (int argc, const char *argv[])
{
  if (argc < 3)
    return 1;

  FILE *in = fopen (argv[1], "rb");
  FILE *out = fopen (argv[2], "wt");

  if (!in || !out)
    return 1;

  fprintf (out, "char %s_data[] = {\n  ", argv[3]);
  int n = 0;
  while (1)
    {
      unsigned char c;
      if (fread (&c, 1, 1, in) == 0)
	break;
      if (n == 0)
	fprintf (out, "0x%x", c);
      else if (n % 15)
	fprintf (out, ", 0x%x", c);
      else
	fprintf (out, ",\n  0x%x", c);
      n++;
    }

  fprintf (out, "};\nint %s_len = %d;\n", argv[3], n);
  fclose (in);
  fclose (out);
  return 0;
}
