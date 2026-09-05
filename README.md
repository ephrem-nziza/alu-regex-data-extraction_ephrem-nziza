# ALU Regex Data Extraction & Secure Validation

This program reads a text file and pulls out useful information from
it, things like emails, card numbers, phone numbers, links, hashtags,
and times. Before it trusts any of that text, it checks it for unsafe
patterns first, and once it finds sensitive data, it hides most of it
before saving the results.

Rename this folder to `alu-regex-data-extraction_{YourGithubUsername}`
before you submit it.

# Folder layout

alu-regex-data-extraction_{YourGithubUsername}/
├── input/
│ └── raw-text.txt sample text to read
├── src/
│ └── main.py the program
├── output/
│ └── sample-output.json the result, created by running the program
└── README.md


# How to run it

You need Python 3.8 or newer, and nothing else. No extra packages to
install.

```bash
cd src
python main.py
```

This reads `../input/raw-text.txt`, prints a short summary to the
screen, and saves the full result to `../output/sample-output.json`.
Swap in your own text file if you want to test it on something else,
then just run it again.

# What it actually finds

Emails are picked up with a normal email pattern, and then checked a
second time to see if they belong to ALU. Addresses ending in
`@alueducation.com` get marked as official, ones ending in
`@alumni.alueducation.com` get marked as alumni, and ones ending in
`@si.alueducation.com` get marked as SI. Anything else just gets
marked as external.

Credit card numbers go through two checks, not one. First, the program
looks for anything shaped like a card number, something with 13 to 19
digits. But looking right isn't the same as being right, so every
match also goes through a Luhn check, which is the same simple math
test real payment systems use to catch a mistyped card number. Only
numbers that pass both checks come out marked as valid.

Phone numbers are trickier because people write them so many
different ways. The program casts a wide net first, then narrows it
down by counting digits, since a real phone number almost always has
somewhere between 7 and 15 digits.

Links are picked up if they start with `http://`, `https://`, or
`www.`. Hashtags are picked up when a `#` is followed by a letter,
which sounds small but actually matters, since without that rule,
something like "Ticket #10234" would get wrongly treated as a
hashtag. And times are matched in both styles people actually use,
the 12-hour kind like `9:30 AM` and the 24-hour kind like `21:00`.

# Why some of the output is hidden

Emails and card numbers are sensitive, so the program never writes
the full value anywhere. For a credit card, only the last four digits
are kept, along with whether it passed the Luhn check. For an email,
only the first and last letter of the name part are kept, everything
in between gets blanked out. Nothing full or raw is ever printed to
the screen either, only counts and short summaries.

# How the safety check works

Before the program looks for any data at all, it checks every single
line of the text for a few patterns that tend to show up in unsafe or
malicious input: a script tag, common SQL command words like DROP
TABLE, template code wrapped in double curly braces, a repeated `../`
used to escape a folder, and a null byte marker.

If a line matches any of those, the whole line gets thrown out before
extraction even starts. That's on purpose. Rather than trying to
carefully separate the "safe" bit of a suspicious line from the
"unsafe" bit, which is fragile and easy to get wrong, the program just
drops the entire line and moves on.

The sample input file has a section clearly labeled as test data,
right at ticket #10237. It isn't a real message, and nothing in it is
meant to actually run as code. It just contains five short, clearly
labeled patterns used to check that the safety check is actually
working, and you can confirm all five get caught by looking at the
safety report in the output file after running the program.

# A few things to know

A pattern can only tell you a number looks like a card number, it
can't tell you whether that number is real. That's the whole reason
the Luhn check exists as a separate step done after the pattern
match, rather than folding everything into one regex.

The hashtag pattern requires a letter right after the `#` for a
reason. An earlier version didn't have that requirement, and it kept
mistakenly grabbing things like "Ticket #10234" as if they were
hashtags.

Phone number matching still isn't perfect, and that's worth being
honest about. Because real numbers show up in so many formats, the
pattern stays wide on purpose, and a digit-count filter cleans up
obvious junk afterward. Every so often it might still catch a piece
of a longer number, like part of a credit card or a reference number
(for example, a chunk of an invoice ID like INV-2026-00981 can look
like a phone number). That's a real limitation of reading plain text
without extra clues like a "Phone:" label next to the number, and
it's called out here instead of hidden.

Finally, the ALU email checks are anchored to the actual end of the
string with a `$`. Without that, something like
`fake@alueducation.com.badsite.com` would wrongly pass as a real ALU
address, just because it contains the right text somewhere inside it,
even though it doesn't actually end with it.

# Regenerating the sample output

`output/sample-output.json` isn't written by hand, it's produced by
running `python main.py`. If you change the input file, just run the
program again and it'll create a fresh, matching output file.
