| Check          | Sub-check                                                                         | Who | Completion Date | Issue #'s |
|----------------|-----------------------------------------------------------------------------------|-----|-----------------|-----------|
|Logical checks| Proper profile directory structure	[1]						|Dan Haynes (reviewed all controls)|*|16, 17, 18|
||JSON output review (e.g., pass/fail on ,<br>hardened, not hardened, edge cases, etc.)|*|*|7|
||InSpec syntax checker|Dan Haynes (reviewed all controls)|11/19/2018|1, 15|
||Local commands focused on target not the runner [2]|Dan Haynes (reviewed all controls)|10/26/2018|*|
|Quality checks|Alignment (including tagging) to original<br> standard (i.e. STIG, CIS Benchmark, NIST Tags)|*|*|6, 11, 12, 13, 20|
||Control robustness (can the control be improved to make it less brittle - not necessarily a blocker on initial releases)|Dan Haynes (reviewed all controls)|*|3, 5, 8, 14|
||Descriptive output for findings details (review JSON for findings information that may be confusing to SCA like NilCLass, etc.)|Dan Haynes|*|21|
||Documentation quality (i.e. README)<br> novice level instructions including prerequisites|*|*|*|
||Consistency across other profile conventions |*|*|*|
||Spelling, grammar,linting (e.g., rubocop, etc.)|Dan Haynes (reviewed all controls)|*|4, 9, 23|
||Removing debugging documentation and code|Dan Haynes (reviewed all controls)|*|*|
| Error handling |“Profile Error” containment: “null” responses <br>should only happen if InSpec is run with incorrect privileges (e.g., code fails to reach a describe statement for every control. inspec check can do this. It will say no defined tests)|Dan Haynes (reviewed all controls)|*|19|
||Slowing the target (e.g. filling up disk, CPU spikes)|Dan Haynes (reviewed all controls)|*|*|
||Check for risky commands (e.g. rm, del, purge, etc.)|Eugene Aronne|11/16/2018|*|
||Check for “stuck” situations (e.g., profile goes on forever due to infinite loop, very large data sets, etc.)|Dan Haynes (reviewed all controls)|*|22|


[1] https://www.inspec.io/docs/reference/profiles/

[2] https://www.inspec.io/docs/reference/style/ (see "Avoid Shelling Out")

Another tip is to cat all the controls into a single file so you don't have to open every individaul file and try to keep track of where you are and which one is next.
