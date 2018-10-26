package devliving.online.securedpreferencestoresample

import android.content.Context
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import devliving.online.securedpreferencestore.EncryptionManager
import android.content.SharedPreferences
import devliving.online.securedpreferencestore.EncryptionManager2
import devliving.online.securedpreferencestore.Logger
import devliving.online.securedpreferencestore.SecuredPreferenceStore
import java.lang.Exception
import java.security.KeyStore


/**
 * Created by NienLe on 26,October,2018
 * Midsummer.
 * Ping me at nienbkict@gmail.com
 * Happy coding ^_^
 */
class SampleActivity : AppCompatActivity() {

    private lateinit var encryptionManager: EncryptionManager2
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_sample)
        val preferences = getSharedPreferences("sample", Context.MODE_PRIVATE)
        encryptionManager = EncryptionManager2(this, preferences, "keyAlias",  "string".toByteArray())
        val ed = encrypt()
        val str = decrypt(ed!!)
        /*val ed = encrypt()
        val str = decrypt(ed)*/
    }



    private fun encrypt() : EncryptionManager2.EncryptedData?{
        val str = "hello tomo"
        val b = str.toByteArray()
        val eD  = encryptionManager.encrypt(b)
        Logger.d("encrypt: $eD")
        return eD
    }

    private fun decrypt(ed: EncryptionManager2.EncryptedData){
        val b = encryptionManager.decrypt(ed)
        val str = String(b!!)
        Logger.d("decrypt: $str")
    }
}