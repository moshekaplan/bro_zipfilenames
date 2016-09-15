module zip_filenames;

# This bro script creates a notice when it detects a zip file 
# containing a file with a known dangerous extension.
# 
# The script extracts the filenames from the Local File Header entries

global DEBUG_MODE = T;

global dangerous_extensions: set[string] = {"bat", "cmd", "exe", "jar", "lnk", "ps1", "scr", "sct", "vb", "vbe", "vbs", "ws", "wsf", "wsh"};

type notice_types: enum {
    ZIP_WITH_DANGEROUS_CONTENT,
};

type DangerousFile: record {
    filename: string;
    ext: string;
};

type DangerousFileVector: vector of DangerousFile;


function print_debug(msg: string){
    if(DEBUG_MODE){
        print msg;
    }
}


function find_filenames(zip_data:string) : vector of string{
    local header_signature = /PK\x03\x04/;
    # This is needed because calling split_string removes the header_signature from the front of the string
    local missing_header_size = 4;
    local filename_length_offset = 26 - missing_header_size;
    local filename_length_size = 2;
    local filename_offset = 30 - missing_header_size;
    
    local filenames : vector of string;
    
    local zip_matches = split_string(zip_data, header_signature);
    for (i in zip_matches){
    	local zip_match = zip_matches[i];
    	if (|zip_match| < filename_offset){
    		next;
    	}
    	
        local length_s = zip_match[filename_length_offset:filename_length_offset+filename_length_size];
        local length = bytestring_to_count(length_s, T);
        
        local fname = zip_match[filename_offset:filename_offset + length];
        filenames[|filenames|] = fname;
    }
    return filenames;
    
}

function get_ext(filename:string): string {
	local fname_split = split_string(filename, /\./);
	local ext = fname_split[|fname_split|-1];
	local lower_ext = to_lower(ext);
	return lower_ext;
}

function get_dangerous_filenames(filenames: vector of string): DangerousFileVector {
	local dangerousfiles = DangerousFileVector();
	for (i in filenames){
		local filename = filenames[i];
		local ext = get_ext(filename);
		if(ext in dangerous_extensions){
			print_debug( fmt("%s is dangerous! Extension of .%s!", filename, ext));
			dangerousfiles[|dangerousfiles|] = DangerousFile($filename=filename, $ext=ext);
		}
	}
	return dangerousfiles;
}

function generate_notice(f: fa_file, filecount:count, dangerousfiles:DangerousFileVector, other_exts:vector of string){
	# Build the message for the notice

	local source_info = "";
	if(f$source == "HTTP"){
		source_info = fmt("Executable with found in zipfile downloaded from: %s.", HTTP::build_url_http(f$http));
	}
	else{
		source_info = fmt("Executable found in zipfile from %s.", f$source );
	}
	print_debug(source_info);

	local dangerous_fnames : vector of string;
	# Store as a set to avoid duplicates
	local dangerous_exts_set: set[string];
	
	for(i in dangerousfiles){
		local entry = dangerousfiles[i];
		dangerous_fnames[|dangerous_fnames|] = entry$filename;
		add dangerous_exts_set[entry$ext];
	}
	
	# Convert set back to a vector for printing
	local dangerous_exts: vector of string;
	for(ext in dangerous_exts_set){
		dangerous_exts[|dangerous_exts|] = ext;
	}
	#TODO: Sort dangerous_exts
	
	local zipfile_count_msg = fmt(" Zipfile contains %d files.", filecount);
	local filenames_msg = fmt(" Filenames=\"%s\"", join_string_vec(dangerous_fnames, ":"));
	local ext_msg = fmt(" Dangerous Extensions=\"%s\"", join_string_vec(dangerous_exts, ":"));
	local other_exts_msg = fmt(" Other Extensions=\"%s\"", join_string_vec(other_exts, ":"));
	
	local notice_data = "Trigger info:" + filenames_msg + ext_msg + other_exts_msg;
	local msg = source_info + zipfile_count_msg + notice_data;
	local subject = filenames_msg;


    NOTICE([$note=ZIP_WITH_DANGEROUS_CONTENT,
            $msg=msg,
            $sub=subject,
            $f=f
            ]);
}

# Event handlers
event zip_filenames::zip_filenames(f: fa_file, data:string){
    # Build a list of filenames
    local filenames = find_filenames(data);
	local filecount = |filenames|;
	
	# Check if the zip file is empty
	if (filecount == 0){
    		return;
	}
	
	# Check if any of the files in the zipfile have a dangerous extension
	local dangerous_filenames = get_dangerous_filenames(filenames);
	if( |dangerous_filenames| == 0 ){
		return;
	}

	# Build a list of the benign extensions
	local other_exts_set : set[string];
	for (i in filenames){
		local filename = filenames[i];
		local ext = get_ext(filename);
		if (ext !in dangerous_extensions){
			add other_exts_set[ext];
		}
	}

	# Convert set back to a vector
	local other_exts : vector of string;
	for(ext in other_exts_set){
		other_exts[|other_exts|] = ext;
	}
	#TODO: Sort other_exts
	

	# Alert on the dangerous files
	generate_notice(f, filecount, dangerous_filenames, other_exts);
}


event file_sniff(f: fa_file, meta: fa_metadata)
{
    if ( (f$source == "HTTP" || f$source == "SMTP") && meta?$mime_type && "application/zip" in meta$mime_type ){
        Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=zip_filenames::zip_filenames]);
	}
}
