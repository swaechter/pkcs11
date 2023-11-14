package ch.swaechter.pkcs11.functions;

import ch.swaechter.pkcs11.Pkcs11Exception;
import ch.swaechter.pkcs11.headers.CkAttributeValue;
import ch.swaechter.pkcs11.headers.CkResult;
import ch.swaechter.pkcs11.templates.Template;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.List;

import static java.lang.foreign.ValueLayout.*;

/**
 * Initializes an object search operation in the PKCS11 middleware.
 *
 * @author Simon Wächter
 */
public class FindObjectsInitFunction extends AbstractFunction {

    /**
     * Create a new function that initializes an object search operation in the PKCS11 middleware.
     *
     * @param linker       Linker to lookup functions in the library
     * @param loaderLookup Symbol lookup to resolve functions from the linker
     * @param template     Template that provides the memory layouts
     */
    public FindObjectsInitFunction(Linker linker, SymbolLookup loaderLookup, Template template) {
        super(linker, loaderLookup, template);
    }

    /**
     * Invoke the function.
     *
     * @param arena                     Memory arena
     * @param sessionId                 ID of the session
     * @param ckAttributeSearchTemplate Search template
     * @throws Pkcs11Exception Thrown if the session does not exist or the search operation can't be initialized
     */
    public void invokeFunction(Arena arena, long sessionId, List<CkAttributeValue> ckAttributeSearchTemplate) throws Pkcs11Exception {
        try {
            // Create a struct array with the attributes
            MemorySegment attributesMemorySegment = arena.allocate(MemoryLayout.sequenceLayout(ckAttributeSearchTemplate.size(), getTemplate().getCkAttributeLayout()));

            // Fill in the values
            for (int i = 0; i < ckAttributeSearchTemplate.size(); i++) {
                // Get the attribute
                CkAttributeValue ckAttribute = ckAttributeSearchTemplate.get(i);

                // Set the type
                getTemplate().getCkAttributeTypeHandle().set(attributesMemorySegment.asSlice(i * getTemplate().getCkAttributeLayout().byteSize()), ckAttribute.type().value);

                // Set the value
                if (ckAttribute.pValue() != null) {
                    // Allocate the object class
                    MemorySegment objectClassMemorySegment = arena.allocate(JAVA_INT_UNALIGNED, ckAttribute.pValue());

                    // Set the value and length
                    getTemplate().getCkAttributePValueHandle().set(attributesMemorySegment.asSlice(i * getTemplate().getCkAttributeLayout().byteSize()), objectClassMemorySegment);
                    getTemplate().getCkAttributeValueLenHandle().set(attributesMemorySegment.asSlice(i * getTemplate().getCkAttributeLayout().byteSize()), (int) objectClassMemorySegment.byteSize());
                } else {
                    // Set a missing value with zero length
                    getTemplate().getCkAttributePValueHandle().set(attributesMemorySegment.asSlice(i * getTemplate().getCkAttributeLayout().byteSize()), MemorySegment.NULL);
                    getTemplate().getCkAttributeValueLenHandle().set(attributesMemorySegment.asSlice(i * getTemplate().getCkAttributeLayout().byteSize()), 0);
                }
            }

            // Invoke the function
            FunctionDescriptor functionDescriptor = FunctionDescriptor.of(JAVA_INT, JAVA_INT, ValueLayout.ADDRESS.withTargetLayout(MemoryLayout.sequenceLayout(JAVA_BYTE)), JAVA_INT);
            MethodHandle methodHandle = downCallHandle("C_FindObjectsInit", functionDescriptor);
            CkResult ckResult = CkResult.valueOf((int) methodHandle.invokeExact((int) sessionId, attributesMemorySegment, 1));
            if (ckResult != CkResult.CKR_OK) {
                throw new Pkcs11Exception("C_FindObjectsInit failed", ckResult);
            }
        } catch (Throwable throwable) {
            throw new Pkcs11Exception("C_FindObjectsInit failed: " + throwable.getMessage(), throwable);
        }
    }
}
