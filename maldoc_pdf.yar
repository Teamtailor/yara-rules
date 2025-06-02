rule possible_exploit : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3

	strings:
		$magic = { 25 50 44 46 }

		$attrib0 = /\/JavaScript /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/

		$action0 = /\/Action/
		$action1 = "Array"
		$shell = "A"
		$cond0 = "unescape"
		$cond1 = "String.fromCharCode"

		$nop = "%u9090%u9090"
	condition:
		$magic in (0..1024) and (2 of ($attrib*)) or ($action0 and #shell > 10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}

rule shellcode_blob_metadata : PDF raw
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "When there's a large Base64 blob inserted into metadata fields it often indicates shellcode to later be decoded"
                weight = 4
        strings:
                $magic = { 25 50 44 46 }

                $reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/ //~6k was observed in BHEHv2 PDF exploits holding the shellcode
                $reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
                $reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
                $reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
                $reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
                $reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

        condition:
                $magic in (0..1024) and 1 of ($reg*)
}

rule suspicious_js : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3

	strings:
		$magic = { 25 50 44 46 }

		$attrib0 = /\/OpenAction /
		$attrib1 = /\/JavaScript /

		$js0 = "eval"
		$js1 = "Array"
		$js2 = "String.fromCharCode"

	condition:
		$magic in (0..1024) and all of ($attrib*) and 2 of ($js*)
}

rule suspicious_embed : PDF raw
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "https://feliam.wordpress.com/2010/01/13/generic-pdf-exploit-hider-embedpdf-py-and-goodbye-av-detection-012010/"
		weight = 2

	strings:
		$magic = { 25 50 44 46 }

		$meth0 = /\/Launch/
		$meth1 = /\/GoTo(E|R)/ //means go to embedded or remote
		$attrib0 = /\/URL /
		$attrib1 = /\/Action/
		$attrib2 = /\/Filespec/

	condition:
		$magic in (0..1024) and 1 of ($meth*) and 2 of ($attrib*)
}

rule PDF_NamedActions_Print_SaveAs_Close : PDF
{
    meta:
        description = "Detects PDF files containing both suspicous launch actions and named actions: /Print, /SaveAs, or /Close"
        author = "JohanT"
        date = "2025-05-27"
        category = "pdf"

    strings:
        $magic = { 25 50 44 46 }

        $attrib0 = /\/Launch/
        $attrib1 = /\/URL /
        $attrib2 = /\/Action/
        $attrib3 = /\/OpenAction/
        $attrib4 = /\/F /

        $named_action_print   = "/S /Named /N /Print"
        $named_action_print2  = "/S/Named/N/Print"
        $named_action_saveas  = "/S /Named /N /SaveAs"
        $named_action_saveas2 = "/S/Named/N/SaveAs"
        $named_action_close   = "/S /Named /N /Close"
        $named_action_close2  = "/S/Named/N/Close"

    condition:
        $magic in (0..1024)
        and any of ($attrib*)
        and any of ($named_action*)
}
