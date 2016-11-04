package pt.isel.si.firstserie.application.command;

import java.io.File;

/**
 * TODO: Commentary
 */
public interface ICommand {

    /**
     *  Executes a command
     *
     * @param file file of the .cer or .pfx
     * @param jwFile file where the jwt or the jwe is being held
     * @throws Exception
     */
    void execute(File file, File jwFile) throws Exception;

}
